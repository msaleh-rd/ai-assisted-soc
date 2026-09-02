"""Tests for Compounding Memory (Wave 3, Phase J)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.postgres import Base
from backend.services.memory.distillation import (
    CompoundingMemory,
    SignaturePrior,
    build_alert_signature,
    MIN_SAMPLES_FOR_ADJUSTMENT,
    MAX_ADJUSTMENT,
)
from backend.services.investigation_context import InvestigationContext
from backend.services.orchestrator import TriageAgent
from backend.services.llm_client import TriageOutput, Entity


@pytest.fixture
def test_session_factory():
    """A fresh in-memory SQLite DB per test, with all known tables created."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    yield factory
    engine.dispose()


class TestBuildAlertSignature:
    def test_combines_classification_tactic_technique(self):
        assert build_alert_signature("Ransomware", "Impact", "T1486") == "ransomware:impact:t1486"

    def test_missing_fields_are_omitted(self):
        assert build_alert_signature("phishing") == "phishing"

    def test_all_missing_returns_unknown(self):
        assert build_alert_signature("") == "unknown"


class TestSignaturePrior:
    def test_false_positive_rate_and_prior_confidence(self):
        prior = SignaturePrior(alert_signature="x", total_count=4, false_positive_count=1)
        assert prior.false_positive_rate == 0.25
        assert prior.prior_confidence == 0.75

    def test_zero_total_count_is_safe(self):
        prior = SignaturePrior(alert_signature="x")
        assert prior.false_positive_rate == 0.0
        assert prior.prior_confidence == 1.0


class TestRecordVerdictAndDistill:
    def test_distill_computes_priors_from_seeded_history(self, test_session_factory):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", test_session_factory):
            for i in range(3):
                memory.record_verdict(f"inv-confirmed-{i}", "ransomware:impact:t1486", "confirmed_incident", risk_score=0.9)
            memory.record_verdict("inv-fp-1", "ransomware:impact:t1486", "false_positive", risk_score=0.3)

            report = memory.distill()

        assert report.signatures_processed == 1
        prior = report.priors["ransomware:impact:t1486"]
        assert prior.total_count == 4
        assert prior.false_positive_count == 1
        assert prior.false_positive_rate == 0.25

    def test_distill_with_no_database_configured_returns_empty(self):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", None):
            report = memory.distill()
        assert report.signatures_processed == 0

    def test_record_verdict_never_raises_without_database(self):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", None):
            memory.record_verdict("inv-x", "sig", "false_positive")  # must not raise


class TestGetMemoryVerdictAdjustment:
    def test_unknown_signature_returns_zero(self):
        memory = CompoundingMemory()
        assert memory.get_memory_verdict_adjustment("never-seen") == 0.0

    def test_insufficient_samples_returns_zero(self, test_session_factory):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", test_session_factory):
            memory.record_verdict("inv-1", "phishing:initial-access:t1566", "confirmed_incident")
            memory.distill()
        assert memory.get_memory_verdict_adjustment("phishing:initial-access:t1566") == 0.0
        assert MIN_SAMPLES_FOR_ADJUSTMENT > 1  # sanity: the seeded sample count is below threshold

    def test_always_confirmed_signature_gets_max_positive_adjustment(self, test_session_factory):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", test_session_factory):
            for i in range(5):
                memory.record_verdict(f"inv-{i}", "lateral_movement:lateral-movement:t1021.001", "confirmed_incident")
            memory.distill()
        adjustment = memory.get_memory_verdict_adjustment("lateral_movement:lateral-movement:t1021.001")
        assert adjustment == pytest.approx(MAX_ADJUSTMENT)

    def test_always_false_positive_signature_gets_max_negative_adjustment(self, test_session_factory):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", test_session_factory):
            for i in range(5):
                memory.record_verdict(f"inv-{i}", "benign_admin:execution:t1059", "false_positive")
            memory.distill()
        adjustment = memory.get_memory_verdict_adjustment("benign_admin:execution:t1059")
        assert adjustment == pytest.approx(-MAX_ADJUSTMENT)

    def test_adjustment_never_exceeds_bound_for_mixed_history(self, test_session_factory):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", test_session_factory):
            for i in range(3):
                memory.record_verdict(f"inv-fp-{i}", "mixed:sig:t0000", "false_positive")
            for i in range(3):
                memory.record_verdict(f"inv-tp-{i}", "mixed:sig:t0000", "confirmed_incident")
            memory.distill()
        adjustment = memory.get_memory_verdict_adjustment("mixed:sig:t0000")
        assert -MAX_ADJUSTMENT <= adjustment <= MAX_ADJUSTMENT
        assert adjustment == pytest.approx(0.0)


class TestGetExemplars:
    def test_returns_empty_for_unknown_signature(self):
        memory = CompoundingMemory()
        assert memory.get_exemplars("never-seen") == []

    def test_returns_seeded_investigation_ids(self, test_session_factory):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", test_session_factory):
            for i in range(3):
                memory.record_verdict(f"inv-{i}", "ransomware:impact:t1486", "confirmed_incident")
            memory.distill()
        exemplars = memory.get_exemplars("ransomware:impact:t1486")
        assert len(exemplars) == 3
        assert all(eid.startswith("inv-") for eid in exemplars)


class TestClear:
    def test_clear_resets_priors(self, test_session_factory):
        memory = CompoundingMemory()
        with patch("backend.database.connection.SessionLocal", test_session_factory):
            for i in range(5):
                memory.record_verdict(f"inv-{i}", "sig", "confirmed_incident")
            memory.distill()
        assert memory.get_memory_verdict_adjustment("sig") == pytest.approx(MAX_ADJUSTMENT)

        memory.clear()

        assert memory.get_memory_verdict_adjustment("sig") == 0.0
        assert memory.get_exemplars("sig") == []


class TestTriageAgentAppliesMemoryAdjustment:
    @pytest.mark.asyncio
    async def test_confidence_boosted_for_historically_confirmed_signature(self):
        """A signature with a strong confirmed-incident history should nudge
        Triage's confidence upward by exactly MAX_ADJUSTMENT, and the adjustment
        must be recorded on findings for auditability."""
        seeded_memory = CompoundingMemory()
        seeded_memory._priors["known_bad:initial access:t1078"] = SignaturePrior(
            alert_signature="known_bad:initial access:t1078",
            total_count=10,
            false_positive_count=0,
        )

        mock_result = TriageOutput(
            severity="High",
            classification="known_bad",
            tactic="Initial Access",
            technique="T1078",
            entities_identified=[Entity(type="host", id="HOST-MEM-1")],
            requires_immediate_action=True,
            initial_assessment="Recurring known-bad pattern.",
            confidence=0.60,
        )
        mock_structured_llm = MagicMock()
        mock_structured_llm.ainvoke = AsyncMock(return_value=mock_result)
        mock_chat = MagicMock()
        mock_chat.with_structured_output.return_value = mock_structured_llm

        agent = TriageAgent()
        context = InvestigationContext(alert_data={"alert_id": "alert-mem-1", "description": "Recurring known-bad login on HOST-MEM-1"})

        with patch("backend.services.llm_client.get_llm", return_value=mock_chat), \
             patch("backend.services.memory.distillation.compounding_memory", seeded_memory):
            report = await agent.execute({}, context)

        assert report.findings["alert_signature"] == "known_bad:initial access:t1078"
        assert report.findings["memory_adjustment"] == pytest.approx(MAX_ADJUSTMENT)
        assert report.confidence == pytest.approx(0.60 + MAX_ADJUSTMENT)

    @pytest.mark.asyncio
    async def test_unseen_signature_has_no_effect_on_confidence(self):
        agent = TriageAgent()
        mock_result = TriageOutput(
            severity="Medium",
            classification="brand_new_pattern",
            tactic="Execution",
            technique="T1059",
            entities_identified=[Entity(type="host", id="HOST-MEM-2")],
            requires_immediate_action=False,
            initial_assessment="Never-before-seen pattern.",
            confidence=0.55,
        )
        mock_structured_llm = MagicMock()
        mock_structured_llm.ainvoke = AsyncMock(return_value=mock_result)
        mock_chat = MagicMock()
        mock_chat.with_structured_output.return_value = mock_structured_llm

        context = InvestigationContext(alert_data={"alert_id": "alert-mem-2", "description": "Something new on HOST-MEM-2"})

        with patch("backend.services.llm_client.get_llm", return_value=mock_chat), \
             patch("backend.services.memory.distillation.compounding_memory", CompoundingMemory()):
            report = await agent.execute({}, context)

        assert report.findings["memory_adjustment"] == 0.0
        assert report.confidence == pytest.approx(0.55)
