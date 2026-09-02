"""Tests for the Investigation Swarm (Wave 3, Phase I)."""

import pytest
from unittest.mock import AsyncMock, patch

from backend.services.investigation_context import InvestigationContext
from backend.services.hypothesis_swarm import (
    InvestigationSwarm,
    HypothesisAgent,
    SwarmResult,
    investigation_swarm,
)
from backend.services.llm_client import HypothesisItem, SwarmHypothesesOutput
from backend.services.supervisor import SupervisorAgent


SAMPLE_ALERT = {
    "alert_id": "raindrop_stuck_loop_001",
    "description": "Suspicious PowerShell activity: raindrop.ps1 executed with encoded command, "
                    "reaching out to multiple internal hosts",
    "severity": 5,
    "severity_name": "Critical",
    "user_name": "svc_backup",
    "computer_name": "WKS-042",
    "timestamp": "2026-08-24T09:52:29.446Z",
    "source": "EDR",
}


def _build_complex_context() -> InvestigationContext:
    context = InvestigationContext(alert_data=SAMPLE_ALERT, use_ai_planner=True)
    context.add_entity("WKS-042", "host")
    context.add_entity("svc_backup", "user")
    context.add_entity("DC-01", "host")
    context.add_entity("192.168.1.50", "ip")
    context.mitre_techniques = ["T1059.001", "T1021.001", "T1003"]
    # A timeline has already been compressed, but RCA still hasn't converged --
    # the "stuck in a loop" scenario: repeated evidence gathering with no RCA yet.
    context.compressed_events = {"timeline": [{"action": "encoded powershell command", "risk_score": 0.85}]}
    context.action_counts["gather_evidence"] = 3
    return context


class TestShouldSwarm:
    """Unit tests for InvestigationSwarm.should_swarm() threshold logic."""

    def test_simple_case_does_not_swarm(self):
        swarm = InvestigationSwarm()
        context = InvestigationContext(alert_data=SAMPLE_ALERT)
        context.add_entity("WKS-042", "host")
        assert swarm.should_swarm(context) is False

    def test_complex_case_by_entity_count_swarms(self):
        swarm = InvestigationSwarm()
        context = InvestigationContext(alert_data=SAMPLE_ALERT)
        context.add_entity("WKS-042", "host")
        context.add_entity("svc_backup", "user")
        context.add_entity("DC-01", "host")
        assert swarm.should_swarm(context) is True

    def test_complex_case_by_technique_count_swarms(self):
        swarm = InvestigationSwarm()
        context = InvestigationContext(alert_data=SAMPLE_ALERT)
        context.add_entity("WKS-042", "host")
        context.mitre_techniques = ["T1059.001", "T1021.001", "T1003"]
        assert swarm.should_swarm(context) is True

    def test_threshold_is_exactly_three(self):
        swarm = InvestigationSwarm()
        context = InvestigationContext(alert_data=SAMPLE_ALERT)
        context.add_entity("a", "host")
        context.add_entity("b", "host")
        assert swarm.should_swarm(context) is False
        context.add_entity("c", "host")
        assert swarm.should_swarm(context) is True


class TestRunSwarm:
    """Unit tests for InvestigationSwarm.run_swarm() generation + scoring/ranking."""

    @pytest.mark.asyncio
    async def test_run_swarm_ranks_hypotheses_by_evidence_overlap(self):
        """A hypothesis whose supporting techniques overlap with observed techniques
        and has no contradicting entities present should outrank a low-confidence,
        low-overlap alternative."""
        context = _build_complex_context()
        swarm = InvestigationSwarm()

        mock_output = SwarmHypothesesOutput(hypotheses=[
            HypothesisItem(
                hypothesis="Lateral movement via compromised service account credentials",
                supporting_techniques=["T1021.001", "T1003"],
                contradicting_signals=[],
                confidence=0.8,
            ),
            HypothesisItem(
                hypothesis="Benign scheduled backup script misidentified",
                supporting_techniques=[],
                contradicting_signals=["DC-01", "192.168.1.50"],
                confidence=0.4,
            ),
        ])

        mock_structured_llm = AsyncMock()
        mock_structured_llm.ainvoke.return_value = mock_output
        mock_llm = AsyncMock()
        mock_llm.with_structured_output = lambda schema: mock_structured_llm

        with patch("backend.services.hypothesis_swarm.get_llm", return_value=mock_llm):
            result = await swarm.run_swarm(context)

        assert isinstance(result, SwarmResult)
        assert len(result.hypotheses) == 2
        assert result.winning_hypothesis.hypothesis.startswith("Lateral movement")
        assert result.winning_hypothesis.combined_score > result.hypotheses[1].combined_score
        assert "WINNER" in result.debate_notes

    @pytest.mark.asyncio
    async def test_run_swarm_falls_back_to_heuristic_on_llm_failure(self):
        """If the LLM call raises, the swarm still produces a ranked result via the
        deterministic heuristic fallback (never crashes the caller)."""
        context = _build_complex_context()
        swarm = InvestigationSwarm()

        with patch("backend.services.hypothesis_swarm.get_llm", side_effect=RuntimeError("LLM unavailable")):
            result = await swarm.run_swarm(context)

        assert isinstance(result, SwarmResult)
        assert len(result.hypotheses) == 2
        assert result.winning_hypothesis is not None
        assert all(isinstance(h, HypothesisAgent) for h in result.hypotheses)

    @pytest.mark.asyncio
    async def test_contradiction_penalty_lowers_score(self):
        """A hypothesis whose contradicting signals match entities actually present
        in the investigation should score lower than an otherwise identical
        hypothesis with no contradictions."""
        context = _build_complex_context()
        swarm = InvestigationSwarm()

        clean = HypothesisAgent(hypothesis="A", supporting_techniques=["T1003"], contradicting_signals=[], confidence=0.7)
        contradicted = HypothesisAgent(hypothesis="B", supporting_techniques=["T1003"], contradicting_signals=["DC-01"], confidence=0.7)

        scored_clean = await swarm._score_hypothesis(clean, context)
        scored_contradicted = await swarm._score_hypothesis(contradicted, context)

        assert scored_clean.combined_score > scored_contradicted.combined_score


class TestSupervisorSwarmIntegration:
    """Integration tests verifying the guarded swarm branch inside decide_next_step()."""

    @pytest.mark.asyncio
    async def test_supervisor_engages_swarm_when_stuck_and_complex(self):
        """When should_swarm() is True and the investigation is stuck (repeated
        gather_evidence, no RCA findings), decide_next_step() should return the
        swarm-derived perform_rca decision instead of calling the normal LLM path."""
        supervisor = SupervisorAgent()
        context = _build_complex_context()

        winner = HypothesisAgent(
            hypothesis="Lateral movement via compromised service account credentials",
            supporting_techniques=["T1021.001"],
            contradicting_signals=[],
            confidence=0.85,
            evidence_overlap_score=1.0,
            combined_score=0.9,
        )
        fake_result = SwarmResult(hypotheses=[winner], winning_hypothesis=winner, debate_notes="Ranked 1 hypothesis:\n  [0.90] Lateral movement... -> WINNER")

        with patch("backend.services.supervisor.investigation_swarm.should_swarm", return_value=True), \
             patch("backend.services.supervisor.investigation_swarm.run_swarm", new=AsyncMock(return_value=fake_result)):
            decision = await supervisor.decide_next_step(context)

        assert decision.action == "perform_rca"
        assert "Lateral movement" in decision.specific_goal
        assert context.swarm_debate_notes == fake_result.debate_notes

    @pytest.mark.asyncio
    async def test_supervisor_skips_swarm_for_simple_case(self):
        """should_swarm() False -> the swarm branch must not engage, even if
        gather_evidence has been attempted repeatedly."""
        supervisor = SupervisorAgent()
        context = InvestigationContext(alert_data=SAMPLE_ALERT, use_ai_planner=True)
        context.add_entity("WKS-042", "host")
        context.action_counts["gather_evidence"] = 5

        with patch("backend.services.supervisor.get_llm", side_effect=RuntimeError("no LLM in test")), \
             patch("backend.services.supervisor.investigation_swarm.run_swarm", new=AsyncMock()) as mock_run_swarm:
            decision = await supervisor.decide_next_step(context)

        mock_run_swarm.assert_not_called()
        assert decision is not None

    @pytest.mark.asyncio
    async def test_supervisor_falls_through_on_swarm_exception(self):
        """If run_swarm() raises, decide_next_step() must fall through to the
        normal (heuristic fallback, since no LLM configured in test) decision path
        rather than propagating the exception."""
        supervisor = SupervisorAgent()
        context = _build_complex_context()

        with patch("backend.services.supervisor.get_llm", side_effect=RuntimeError("no LLM in test")), \
             patch("backend.services.supervisor.investigation_swarm.should_swarm", return_value=True), \
             patch("backend.services.supervisor.investigation_swarm.run_swarm", new=AsyncMock(side_effect=RuntimeError("boom"))):
            decision = await supervisor.decide_next_step(context)

        assert decision is not None
        assert decision.action in [
            "gather_evidence", "discover_network", "compress_events",
            "perform_rca", "terminate_benign", "finalize_response",
        ]


investigation_swarm_singleton = investigation_swarm  # keep reference to avoid unused-import lint
