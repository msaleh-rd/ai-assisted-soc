"""Unit tests for Phase 3 Response Skills and ResponseSkillExecutor."""

import pytest
from backend.services.response.skill_handlers import ResponseSkillExecutor
from backend.services.response.maturity_gate import (
    AutomationTier,
    BlastRadius,
    MaturityGate,
    SKILL_BLAST_RADIUS,
    MIN_TIER_FOR_AUTO_EXECUTE,
)
from backend.services.response_orchestration import ResponseOrchestrator
from backend.services.rca_engine import ResponseAction, ResponseRecommendation
from backend.services.skills import skill_registry


@pytest.mark.asyncio
async def test_response_skills_discovery():
    """Verify that response skills are discovered and loaded from filesystem."""
    skills = skill_registry.load_phase_skills("response")
    skill_names = {s.name for s in skills}
    
    assert "isolate-host" in skill_names
    assert "block-ip" in skill_names
    assert "block-domain" in skill_names
    assert "kill-process" in skill_names
    assert "reset-credentials" in skill_names
    assert "quarantine-file" in skill_names
    assert "notify-soc-team" in skill_names


@pytest.mark.asyncio
async def test_isolate_host_skill():
    """Test host network isolation skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="isolate-host",
        target="workstation-99",
        parameters={"reason": "Active ransomware spreading"}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "isolated" in res["result"]
    assert "rule_id" in res


@pytest.mark.asyncio
async def test_block_ip_skill():
    """Test firewall IP block skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="block-ip",
        target="192.42.1.174",
        parameters={"direction": "both"}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "192.42.1.174" in res["result"]
    assert "rule_id" in res


@pytest.mark.asyncio
async def test_block_domain_skill():
    """Test DNS sinkhole domain block skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="block-domain",
        target="malicious-c2-server.com",
        parameters={}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "sinkhole" in res["result"]


@pytest.mark.asyncio
async def test_kill_process_skill():
    """Test process termination skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="kill-process",
        target="donotcry",
        parameters={"pids": [4096], "host": "linuxshare"}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "donotcry" in res["result"]
    assert 4096 in res["terminated_pids"]


@pytest.mark.asyncio
async def test_reset_credentials_skill():
    """Test account credential revocation skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="reset-credentials",
        target="compromised_user",
        parameters={}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "compromised_user" in res["result"]
    assert res["sessions_revoked"] > 0


@pytest.mark.asyncio
async def test_quarantine_file_skill():
    """Test file quarantine skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="quarantine-file",
        target="/tmp/malware.exe",
        parameters={}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "malware.exe" in res["result"]
    assert "quarantine_path" in res


@pytest.mark.asyncio
async def test_notify_soc_team_skill():
    """Test SOC team notification skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="notify-soc-team",
        target="incident-42",
        parameters={"message": "Ransomware contained on workstation-99", "channel": "pagerduty"}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "Ransomware contained" in res["result"]
    assert res["channel"] == "pagerduty"


# ----------------------------------------------------------------------------
# L0-L4 Automation Maturity Gate tests
# ----------------------------------------------------------------------------

def _make_action(action: ResponseAction, target: str = "target-1", priority: str = "high") -> ResponseRecommendation:
    return ResponseRecommendation(
        action=action,
        priority=priority,
        target=target,
        description="test action",
        prerequisites=[],
        estimated_time_minutes=5,
        success_criteria=["test"],
        rollback_steps=["test"],
        business_impact="test"
    )


class TestMaturityGate:
    """Unit tests for the L0-L4 automation maturity gate."""

    def test_minimal_blast_radius_auto_executes_at_lowest_tier(self):
        gate = MaturityGate(tier=AutomationTier.L0_OBSERVE)
        decision = gate.evaluate("notify-soc-team")
        assert decision.blast_radius == BlastRadius.MINIMAL
        assert decision.auto_execute is True

    def test_critical_blast_radius_requires_top_tier(self):
        gate = MaturityGate(tier=AutomationTier.L3_CONDITIONAL)
        decision = gate.evaluate("isolate-host")
        assert decision.blast_radius == BlastRadius.CRITICAL
        assert decision.auto_execute is False

        gate.set_tier(AutomationTier.L4_FULL_AUTO)
        decision = gate.evaluate("isolate-host")
        assert decision.auto_execute is True

    def test_medium_blast_radius_gated_below_required_tier(self):
        gate = MaturityGate(tier=AutomationTier.L1_RECOMMEND)
        decision = gate.evaluate("block-ip")
        assert decision.blast_radius == BlastRadius.MEDIUM
        assert decision.auto_execute is False

        gate.set_tier(AutomationTier.L2_SUPERVISED)
        decision = gate.evaluate("block-ip")
        assert decision.auto_execute is True

    def test_unknown_skill_fails_closed_to_critical(self):
        gate = MaturityGate(tier=AutomationTier.L3_CONDITIONAL)
        decision = gate.evaluate("some-brand-new-skill")
        assert decision.blast_radius == BlastRadius.CRITICAL
        assert decision.auto_execute is False

    def test_skill_name_normalization(self):
        gate = MaturityGate(tier=AutomationTier.L4_FULL_AUTO)
        decision_hyphen = gate.evaluate("block-domain")
        decision_underscore = gate.evaluate("block_domain")
        assert decision_hyphen.blast_radius == decision_underscore.blast_radius

    def test_all_known_skills_have_a_mapped_blast_radius(self):
        # Every skill handled by ResponseSkillExecutor should be classified.
        known_skills = [
            "isolate-host", "block-ip", "block-domain", "kill-process",
            "reset-credentials", "patch-system", "update-firewall", "enable-mfa",
            "quarantine-file", "notify-soc-team",
        ]
        for skill in known_skills:
            assert skill in SKILL_BLAST_RADIUS


class TestResponseOrchestratorMaturityGateIntegration:
    """Integration tests: the maturity gate must actually gate execution."""

    @pytest.mark.asyncio
    async def test_low_risk_action_auto_executes_without_approval_callback(self):
        orchestrator = ResponseOrchestrator(
            approval_required=True, automation_tier=AutomationTier.L1_RECOMMEND
        )
        action = _make_action(ResponseAction.ENABLE_MFA, target="user-1")

        calls = []

        async def approval_callback(request):
            calls.append(request)
            return True

        result = await orchestrator._execute_action(action, approval_callback, "containment")

        assert result["success"] is True
        assert calls == []  # never asked for approval
        assert result["gate_decision"].auto_execute is True

    @pytest.mark.asyncio
    async def test_high_risk_action_is_blocked_when_approval_denied(self):
        orchestrator = ResponseOrchestrator(
            approval_required=True, automation_tier=AutomationTier.L1_RECOMMEND
        )
        action = _make_action(ResponseAction.ISOLATE_HOST, target="workstation-1", priority="high")

        async def approval_callback(request):
            return False

        result = await orchestrator._execute_action(action, approval_callback, "containment")

        assert result["success"] is False
        assert result["error"] == "Approval denied"
        assert result["gate_decision"].auto_execute is False

    @pytest.mark.asyncio
    async def test_approval_required_false_bypasses_gate_entirely(self):
        # Used e.g. by Temporal workflows where approval already happened upstream.
        orchestrator = ResponseOrchestrator(approval_required=False)
        action = _make_action(ResponseAction.ISOLATE_HOST, target="workstation-1")

        result = await orchestrator._execute_action(action, None, "containment")

        assert result["success"] is True
        assert "gate_decision" not in result


# ----------------------------------------------------------------------------
# Wave 2 / Phase F: L0-L4 Automation Maturity Gate — full rollout verification
# ----------------------------------------------------------------------------

ALL_RESPONSE_SKILLS = [
    "isolate-host", "block-ip", "block-domain", "kill-process",
    "reset-credentials", "quarantine-file", "notify-soc-team",
]


class TestMaturityGateFullRolloutMatrix:
    """Every response skill x every automation tier must produce the exact
    expected auto-execute/queue-for-approval decision (Wave 2, Phase F)."""

    @pytest.mark.parametrize("skill", ALL_RESPONSE_SKILLS)
    @pytest.mark.parametrize("tier", list(AutomationTier))
    def test_skill_tier_matrix_matches_blast_radius_requirement(self, skill, tier):
        gate = MaturityGate(tier=tier)
        decision = gate.evaluate(skill)
        required_tier = MIN_TIER_FOR_AUTO_EXECUTE[decision.blast_radius]
        expected_auto_execute = tier >= required_tier
        assert decision.auto_execute == expected_auto_execute, (
            f"skill={skill} tier={tier.name} blast_radius={decision.blast_radius.name} "
            f"required_tier={required_tier.name} expected={expected_auto_execute} "
            f"got={decision.auto_execute}"
        )

    def test_every_response_skill_has_a_blast_radius(self):
        for skill in ALL_RESPONSE_SKILLS:
            assert skill in SKILL_BLAST_RADIUS, f"{skill} missing from SKILL_BLAST_RADIUS"


class TestKillSwitchOverridesAutomationTier:
    """The Phase E kill switch must halt/refuse execution regardless of the
    configured automation tier -- including L4_FULL_AUTO, the most permissive
    tier (Wave 2, Phase F: 'wire the kill-switch as the override regardless of
    configured tier')."""

    @pytest.mark.asyncio
    async def test_kill_switch_blocks_even_at_full_auto_tier(self):
        orchestrator = ResponseOrchestrator(
            approval_required=True, automation_tier=AutomationTier.L4_FULL_AUTO
        )
        orchestrator.engage_kill_switch("Emergency override test")
        action = _make_action(ResponseAction.ISOLATE_HOST, target="workstation-1")

        result = await orchestrator._execute_action(action, None, "containment")

        assert result["success"] is False
        assert "kill switch" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_normal_execution_resumes_after_disengage(self):
        orchestrator = ResponseOrchestrator(approval_required=False)
        orchestrator.engage_kill_switch("temporary halt")
        orchestrator.disengage_kill_switch()
        action = _make_action(ResponseAction.ISOLATE_HOST, target="workstation-1")

        result = await orchestrator._execute_action(action, None, "containment")

        assert result["success"] is True

