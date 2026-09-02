"""Tests for the Multi-Model Router (Wave 1 / Phase D, Step 1)."""

import pytest

from backend.services.model_router import ModelRouter, RoutingDecision


@pytest.fixture
def router():
    return ModelRouter()


class TestDeterministicTriageRouting:
    def test_known_ransomware_extension_routes_deterministic(self, router):
        decision = router.route("triage", {"alert_data": {"file_name": "report.docx.locky"}})
        assert decision.tier == "deterministic"
        assert decision.result["severity"] == "Critical"
        assert decision.result["classification"] == "ransomware"
        assert decision.result["confidence"] >= 0.8
        assert "matched_intel" in decision.result

    def test_known_ransomware_note_filename_routes_deterministic(self, router):
        decision = router.route("triage", {"alert_data": {"file_name": "CONTI_README.txt"}})
        assert decision.tier == "deterministic"
        assert decision.result["severity"] == "Critical"
        assert decision.result["classification"] == "ransomware"

    def test_benign_alert_escalates_to_llm(self, router):
        decision = router.route(
            "triage", {"alert_data": {"file_name": "quarterly_report.docx", "description": "Routine document access"}}
        )
        assert decision.tier == "llm"
        assert decision.result is None
        assert decision.source == "llm_client"

    def test_non_triage_task_skips_deterministic_check(self, router):
        decision = router.route("rca", {"alert_data": {"file_name": "evidence.locky"}})
        assert decision.tier == "llm"

    def test_empty_context_escalates_to_llm(self, router):
        decision = router.route("triage", {})
        assert decision.tier == "llm"


class TestRoutingDecisionShape:
    def test_routing_decision_defaults(self):
        decision = RoutingDecision(tier="llm")
        assert decision.result is None
        assert decision.source == ""
        assert decision.reasoning == ""
