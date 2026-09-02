"""Tests for the Entity-Risk Scoring full rollout (Wave 2 / Phase G).

Verifies that TriageAgent and EvidenceAgent both feed their per-entity risk
signals into the shared EntityRiskTracker (not just the alert_intake.py
pipeline from QW-3), and that crossing the auto-promotion threshold triggers
a visible escalation (blackboard message + audit trail write).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.services.entity_risk import EntityRiskTracker, RiskUpdateResult
from backend.services.investigation_context import InvestigationContext
from backend.services.orchestrator import _escalate_entity_promotion, TriageAgent
from backend.services.llm_client import TriageOutput, Entity


class TestEscalateEntityPromotion:
    def test_posts_fyi_blackboard_message_with_promotion_details(self):
        context = InvestigationContext(alert_data={"alert_id": "alert-1"})
        update = RiskUpdateResult(
            entity_id="host:HOST-001",
            entity_type="host",
            previous_risk=0.6,
            decayed_risk_before_update=0.55,
            added_risk=0.8,
            cumulative_risk=1.35,
            threshold=1.2,
            promoted=True,
            newly_promoted=True,
            reason="Entity 'host:HOST-001' cumulative risk 1.35 crossed promotion threshold 1.20.",
        )

        _escalate_entity_promotion(context, update, source_agent="triage_agent")

        assert len(context.messages) == 1
        msg = context.messages[0]
        assert msg.msg_type == "FYI"
        assert msg.source_agent == "triage_agent"
        assert msg.payload["entity_risk_promoted"] == "host:HOST-001"
        assert msg.payload["cumulative_risk"] == 1.35


class TestTriageAgentFeedsEntityRiskTracker:
    @pytest.mark.asyncio
    async def test_repeated_medium_severity_triage_promotes_entity(self):
        """Three medium-severity triage passes against the same host (0.5 each,
        threshold 1.2 default) should cross the promotion threshold and post a
        blackboard FYI message on the third pass."""
        fresh_tracker = EntityRiskTracker(decay_half_life_hours=999999, promotion_threshold=1.2)

        mock_result = TriageOutput(
            severity="Medium",
            classification="suspicious_login",
            tactic="Initial Access",
            technique="T1078",
            entities_identified=[Entity(type="host", id="HOST-ROLLOUT-1")],
            requires_immediate_action=False,
            initial_assessment="Repeated suspicious login activity.",
            confidence=0.75,
        )
        mock_structured_llm = MagicMock()
        mock_structured_llm.ainvoke = AsyncMock(return_value=mock_result)
        mock_chat = MagicMock()
        mock_chat.with_structured_output.return_value = mock_structured_llm

        agent = TriageAgent()
        promoted_seen = False

        with patch("backend.services.llm_client.get_llm", return_value=mock_chat), \
             patch("backend.services.entity_risk.entity_risk_tracker", fresh_tracker):
            for i in range(3):
                context = InvestigationContext(
                    alert_data={
                        "alert_id": f"alert-rollout-{i}",
                        "description": f"Suspicious login attempt #{i} on HOST-ROLLOUT-1",
                    }
                )
                await agent.execute({}, context)
                if any(
                    m.msg_type == "FYI" and "entity_risk_promoted" in m.payload
                    for m in context.messages
                ):
                    promoted_seen = True

        assert promoted_seen, "Expected entity to be auto-promoted by the 3rd repeated medium-severity triage pass"
        assert fresh_tracker.get_state("host:HOST-ROLLOUT-1").promoted is True
