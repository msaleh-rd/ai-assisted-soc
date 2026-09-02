"""Tests for the Playbook Engine (Wave 3, Phase K)."""

from unittest.mock import AsyncMock, patch

import pytest

from backend.services.playbook_engine import (
    PlaybookLoader,
    PlaybookValidationError,
    alert_matches_trigger,
    PlaybookEngine,
    DEFAULT_PLAYBOOKS_DIR,
)
from backend.services.investigation_context import InvestigationContext
from backend.services.orchestrator import AgentReport, AgentStatus


RANSOMWARE_ALERT = {
    "alert_id": "ransom-001",
    "severity_name": "Critical",
    "classification": "ransomware",
    "description": "Ransomware note dropped, files being encrypted (T1486)",
    "computer_name": "HOST-RANSOM-1",
}

BENIGN_ALERT = {
    "alert_id": "benign-001",
    "severity_name": "Low",
    "classification": "informational_event",
    "description": "Routine scheduled task executed successfully.",
}


class TestPlaybookLoader:
    def test_loads_ransomware_playbook_from_repo(self):
        playbooks = PlaybookLoader.load_all(DEFAULT_PLAYBOOKS_DIR)
        ids = [p.id for p in playbooks]
        assert "ransomware-response-v1" in ids

        pb = next(p for p in playbooks if p.id == "ransomware-response-v1")
        assert [s.type for s in pb.steps] == ["isolate_host", "investigate", "notify", "generate_report"]
        assert pb.steps[0].on_failure == "continue"
        assert pb.steps[1].on_failure == "abort"

    def test_missing_required_field_raises(self):
        with pytest.raises(PlaybookValidationError):
            PlaybookLoader.from_dict({"id": "x", "name": "X", "version": "1.0", "trigger": {}})

    def test_unknown_step_type_raises(self):
        raw = {
            "id": "x", "name": "X", "version": "1.0", "trigger": {},
            "steps": [{"id": "s1", "name": "Bad step", "type": "not_a_real_type"}],
        }
        with pytest.raises(PlaybookValidationError):
            PlaybookLoader.from_dict(raw)

    def test_invalid_on_failure_raises(self):
        raw = {
            "id": "x", "name": "X", "version": "1.0", "trigger": {},
            "steps": [{"id": "s1", "name": "S", "type": "notify", "on_failure": "explode"}],
        }
        with pytest.raises(PlaybookValidationError):
            PlaybookLoader.from_dict(raw)

    def test_default_on_failure_is_abort(self):
        raw = {
            "id": "x", "name": "X", "version": "1.0", "trigger": {},
            "steps": [{"id": "s1", "name": "S", "type": "notify"}],
        }
        pb = PlaybookLoader.from_dict(raw)
        assert pb.steps[0].on_failure == "abort"


class TestAlertMatchesTrigger:
    def test_matches_severity_and_tag(self):
        trigger = {"severity": ["critical", "high"], "tags": ["ransomware", "T1486"]}
        assert alert_matches_trigger(RANSOMWARE_ALERT, trigger) is True

    def test_wrong_severity_does_not_match(self):
        trigger = {"severity": ["critical", "high"], "tags": ["ransomware"]}
        assert alert_matches_trigger(BENIGN_ALERT, trigger) is False

    def test_matching_severity_but_no_tag_match_fails(self):
        trigger = {"severity": ["low"], "tags": ["ransomware", "T1486"]}
        assert alert_matches_trigger(BENIGN_ALERT, trigger) is False

    def test_empty_trigger_matches_everything(self):
        assert alert_matches_trigger(BENIGN_ALERT, {}) is True


class TestFindMatchingPlaybook:
    def test_finds_ransomware_playbook_for_matching_alert(self):
        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        matched = engine.find_matching_playbook(RANSOMWARE_ALERT)
        assert matched is not None
        assert matched.id == "ransomware-response-v1"

    def test_no_match_for_benign_alert(self):
        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        assert engine.find_matching_playbook(BENIGN_ALERT) is None


def _fake_agent_report(agent_name: str) -> AgentReport:
    return AgentReport(
        agent_name=agent_name,
        task="fake",
        status=AgentStatus.COMPLETED,
        findings={"classification": "ransomware", "severity": "Critical"},
        confidence=0.9,
    )


class TestExecutePlaybookOrderAndFailureSemantics:
    @pytest.mark.asyncio
    async def test_steps_execute_in_declared_order(self):
        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        playbook = engine.find_matching_playbook(RANSOMWARE_ALERT)
        context = InvestigationContext(alert_data=RANSOMWARE_ALERT)

        success_summary = {"actions_executed": [{"action": "isolate_host"}], "actions_failed": []}

        with patch(
            "backend.services.response_orchestration.ResponseOrchestrator.execute_response_plan",
            new=AsyncMock(return_value=success_summary),
        ), patch(
            "backend.services.orchestrator.TriageAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("triage_agent")),
        ), patch(
            "backend.services.orchestrator.EvidenceAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("evidence_agent")),
        ), patch(
            "backend.services.orchestrator.CompressionAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("compression_agent")),
        ), patch(
            "backend.services.orchestrator.RCAAnalystAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("rca_agent")),
        ):
            result = engine  # keep name short
            exec_result = await engine.execute_playbook(playbook, context)

        assert [r.step_id for r in exec_result.step_results] == ["contain", "investigate", "notify", "report"]
        assert exec_result.aborted is False
        assert all(r.status == "success" for r in exec_result.step_results)

    @pytest.mark.asyncio
    async def test_on_failure_continue_lets_investigation_proceed_after_isolate_host_failure(self):
        """Simulates an isolate-host failure; because that step's on_failure is
        'continue', the playbook must still run the remaining steps."""
        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        playbook = engine.find_matching_playbook(RANSOMWARE_ALERT)
        context = InvestigationContext(alert_data=RANSOMWARE_ALERT)

        failure_summary = {"actions_executed": [], "actions_failed": [{"action": "isolate_host", "error": "host unreachable"}]}

        with patch(
            "backend.services.response_orchestration.ResponseOrchestrator.execute_response_plan",
            new=AsyncMock(return_value=failure_summary),
        ), patch(
            "backend.services.orchestrator.TriageAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("triage_agent")),
        ), patch(
            "backend.services.orchestrator.EvidenceAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("evidence_agent")),
        ), patch(
            "backend.services.orchestrator.CompressionAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("compression_agent")),
        ), patch(
            "backend.services.orchestrator.RCAAnalystAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("rca_agent")),
        ):
            exec_result = await engine.execute_playbook(playbook, context)

        assert exec_result.aborted is False
        step_ids_run = [r.step_id for r in exec_result.step_results]
        assert step_ids_run == ["contain", "investigate", "notify", "report"]
        assert exec_result.step_results[0].status == "failed"
        assert exec_result.step_results[1].status == "success"  # investigate still ran

    @pytest.mark.asyncio
    async def test_on_failure_abort_stops_remaining_steps(self):
        """If the 'investigate' step (on_failure: abort) fails, subsequent
        notify/report steps must never run."""
        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        playbook = engine.find_matching_playbook(RANSOMWARE_ALERT)
        context = InvestigationContext(alert_data=RANSOMWARE_ALERT)

        success_summary = {"actions_executed": [{"action": "isolate_host"}], "actions_failed": []}

        with patch(
            "backend.services.response_orchestration.ResponseOrchestrator.execute_response_plan",
            new=AsyncMock(return_value=success_summary),
        ), patch(
            "backend.services.orchestrator.TriageAgent.execute",
            new=AsyncMock(side_effect=RuntimeError("triage exploded")),
        ):
            exec_result = await engine.execute_playbook(playbook, context)

        assert exec_result.aborted is True
        step_ids_run = [r.step_id for r in exec_result.step_results]
        assert step_ids_run == ["contain", "investigate"]
        assert exec_result.step_results[1].status == "failed"

    @pytest.mark.asyncio
    async def test_retry_semantics_retries_once_then_continues(self):
        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        context = InvestigationContext(alert_data=RANSOMWARE_ALERT)

        from backend.services.playbook_engine import Playbook, PlaybookStep

        call_count = {"n": 0}

        async def flaky_notify(self_arg, step, ctx):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("transient failure")
            from backend.services.playbook_engine import StepResult
            return StepResult(step_id=step.id, step_name=step.name, status="success", detail={})

        playbook = Playbook(
            id="retry-test", name="Retry Test", version="1.0", trigger={},
            steps=[PlaybookStep(id="notify1", name="Notify", type="notify", on_failure="retry")],
        )

        with patch.object(PlaybookEngine, "_run_notify", new=flaky_notify):
            exec_result = await engine.execute_playbook(playbook, context)

        assert call_count["n"] == 2
        assert exec_result.step_results[0].status == "success"
        assert exec_result.step_results[0].retried is True


class TestOrchestratorPlaybookIntegration:
    """End-to-end: OrchestratorAgent._execute_stream_static() engages the
    playbook engine for a matching alert instead of the static 5-phase plan."""

    @pytest.mark.asyncio
    async def test_matching_alert_engages_playbook_and_emits_events(self):
        from backend.services.orchestrator import OrchestratorAgent
        import json as _json

        success_summary = {"actions_executed": [{"action": "isolate_host"}], "actions_failed": []}

        with patch(
            "backend.services.response_orchestration.ResponseOrchestrator.execute_response_plan",
            new=AsyncMock(return_value=success_summary),
        ), patch(
            "backend.services.orchestrator.TriageAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("triage_agent")),
        ), patch(
            "backend.services.orchestrator.EvidenceAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("evidence_agent")),
        ), patch(
            "backend.services.orchestrator.CompressionAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("compression_agent")),
        ), patch(
            "backend.services.orchestrator.RCAAnalystAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("rca_agent")),
        ):
            agent = OrchestratorAgent()
            events = []
            async for evt in agent.execute_stream("Investigate", RANSOMWARE_ALERT, use_ai_planner=False):
                events.append(evt)

        event_types = []
        for raw in events:
            # sse_event() formats as "event: <type>\ndata: <json>\n\n" (or similar) -- extract the type line.
            for line in raw.splitlines():
                if line.startswith("event:"):
                    event_types.append(line.split(":", 1)[1].strip())

        assert "playbook_engaged" in event_types
        assert "playbook_step_complete" in event_types
        assert "run_complete" in event_types
        assert event_types.count("playbook_step_complete") == 4

    @pytest.mark.asyncio
    async def test_non_matching_alert_falls_through_to_static_plan(self):
        from backend.services.orchestrator import OrchestratorAgent

        with patch(
            "backend.services.orchestrator.TriageAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("triage_agent")),
        ), patch(
            "backend.services.orchestrator.EvidenceAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("evidence_agent")),
        ), patch(
            "backend.services.orchestrator.NetworkDiscoveryAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("discovery_agent")),
        ), patch(
            "backend.services.orchestrator.CompressionAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("compression_agent")),
        ), patch(
            "backend.services.orchestrator.RCAAnalystAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("rca_agent")),
        ), patch(
            "backend.services.orchestrator.ResponsePlannerAgent.execute",
            new=AsyncMock(return_value=_fake_agent_report("response_agent")),
        ):
            agent = OrchestratorAgent()
            events = []
            async for evt in agent.execute_stream("Investigate", BENIGN_ALERT, use_ai_planner=False):
                events.append(evt)

        event_types = []
        for raw in events:
            for line in raw.splitlines():
                if line.startswith("event:"):
                    event_types.append(line.split(":", 1)[1].strip())

        assert "playbook_engaged" not in event_types
        assert "run_complete" in event_types

    @pytest.mark.asyncio
    async def test_notify_step_uses_real_response_skill_executor(self):
        from backend.services.playbook_engine import PlaybookStep

        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        context = InvestigationContext(alert_data=RANSOMWARE_ALERT)
        step = PlaybookStep(id="n1", name="Notify SOC", type="notify", params={"channel": "slack", "message": "test"})

        result = await engine._run_notify(step, context)

        assert result.status == "success"
        assert result.detail["action"] == "notify-soc-team"

    @pytest.mark.asyncio
    async def test_generate_report_step_summarizes_context_state(self):
        from backend.services.playbook_engine import PlaybookStep

        engine = PlaybookEngine(playbooks_dir=DEFAULT_PLAYBOOKS_DIR)
        context = InvestigationContext(alert_data=RANSOMWARE_ALERT)
        context.classification = "ransomware"
        context.severity = "Critical"
        context.rca_findings = {"root_cause": "Phishing-delivered ransomware payload", "confidence_score": 0.92}
        step = PlaybookStep(id="r1", name="Report", type="generate_report")

        result = await engine._run_generate_report(step, context)

        assert result.status == "success"
        assert result.detail["root_cause"] == "Phishing-delivered ransomware payload"
        assert result.detail["severity"] == "Critical"
