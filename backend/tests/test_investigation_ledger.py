"""Tests for the Investigation Ledger (Wave 1 / Phase C).

Covers the core ledger service (record/replay/cost-summary/prompt-hash
integrity) and its wiring into the Autonomous ReAct Supervisor's decision
loop, which is the primary agentic instrumentation point.
"""

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.services.investigation_ledger import (
    InvestigationLedger,
    LedgerEntry,
    estimate_tokens,
)
from backend.services.investigation_context import InvestigationContext
from backend.services.supervisor import SupervisorAgent
from backend.services.llm_client import SupervisorDecision


@pytest.fixture
def ledger():
    return InvestigationLedger()


class TestLedgerEntry:
    def test_prompt_hash_computed_automatically(self):
        entry = LedgerEntry(
            investigation_id="inv-1",
            step_index=0,
            agent_name="supervisor_agent",
            phase="supervisor",
            prompt_sent="hello world",
        )
        assert entry.prompt_hash == hashlib.sha256(b"hello world").hexdigest()

    def test_prompt_hash_preserved_if_supplied(self):
        entry = LedgerEntry(
            investigation_id="inv-1",
            step_index=0,
            agent_name="supervisor_agent",
            phase="supervisor",
            prompt_sent="hello world",
            prompt_hash="deadbeef",
        )
        assert entry.prompt_hash == "deadbeef"

    def test_to_dict_roundtrip(self):
        entry = LedgerEntry(
            investigation_id="inv-1",
            step_index=2,
            agent_name="rca_agent",
            phase="rca",
            decision={"root_cause": "x"},
        )
        d = entry.to_dict()
        assert d["investigation_id"] == "inv-1"
        assert d["step_index"] == 2
        assert d["decision"] == {"root_cause": "x"}


class TestEstimateTokens:
    def test_empty_string_is_zero(self):
        assert estimate_tokens("") == 0
        assert estimate_tokens(None) == 0

    def test_nonempty_string_is_at_least_one(self):
        assert estimate_tokens("hi") >= 1

    def test_roughly_four_chars_per_token(self):
        text = "a" * 400
        assert estimate_tokens(text) == 100


class TestInvestigationLedgerRecordReplay:
    def test_record_returns_ordered_step_indices(self, ledger):
        e0 = ledger.record("inv-1", "triage_agent", "triage", prompt_sent="p0")
        e1 = ledger.record("inv-1", "supervisor_agent", "supervisor", prompt_sent="p1")
        e2 = ledger.record("inv-1", "rca_agent", "rca", prompt_sent="p2")

        assert [e0.step_index, e1.step_index, e2.step_index] == [0, 1, 2]

        replayed = ledger.replay("inv-1")
        assert [e.agent_name for e in replayed] == ["triage_agent", "supervisor_agent", "rca_agent"]
        assert [e.phase for e in replayed] == ["triage", "supervisor", "rca"]

    def test_replay_is_isolated_per_investigation(self, ledger):
        ledger.record("inv-1", "triage_agent", "triage")
        ledger.record("inv-2", "triage_agent", "triage")

        assert len(ledger.replay("inv-1")) == 1
        assert len(ledger.replay("inv-2")) == 1

    def test_replay_unknown_investigation_returns_empty(self, ledger):
        assert ledger.replay("does-not-exist") == []

    def test_prompt_hash_matches_independent_recompute(self, ledger):
        prompt = "SYSTEM PROMPT\n\nUSER PROMPT WITH ENTITIES"
        entry = ledger.record("inv-1", "supervisor_agent", "supervisor", prompt_sent=prompt)
        expected_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        assert entry.prompt_hash == expected_hash

        replayed = ledger.replay("inv-1")[0]
        assert replayed.prompt_hash == expected_hash

    def test_clear_removes_in_memory_entries(self, ledger):
        ledger.record("inv-1", "triage_agent", "triage")
        ledger.clear("inv-1")
        assert ledger.replay("inv-1") == []


class TestCostSummary:
    def test_aggregates_tokens_and_latency_by_agent(self, ledger):
        ledger.record(
            "inv-1", "triage_agent", "triage",
            tokens_in=100, tokens_out=50, latency_ms=200,
        )
        ledger.record(
            "inv-1", "supervisor_agent", "supervisor",
            tokens_in=300, tokens_out=100, latency_ms=400,
        )
        ledger.record(
            "inv-1", "supervisor_agent", "supervisor",
            tokens_in=150, tokens_out=75, latency_ms=100,
        )

        summary = ledger.get_cost_summary("inv-1")
        assert summary["investigation_id"] == "inv-1"
        assert summary["total_steps"] == 3
        assert summary["total_tokens_in"] == 550
        assert summary["total_tokens_out"] == 225
        assert summary["total_tokens"] == 775
        assert summary["total_latency_ms"] == 700

        assert summary["by_agent"]["triage_agent"]["calls"] == 1
        assert summary["by_agent"]["supervisor_agent"]["calls"] == 2
        assert summary["by_agent"]["supervisor_agent"]["tokens_in"] == 450
        assert summary["by_agent"]["supervisor_agent"]["latency_ms"] == 500

    def test_cost_summary_for_unknown_investigation_is_zeroed(self, ledger):
        summary = ledger.get_cost_summary("nope")
        assert summary["total_steps"] == 0
        assert summary["total_tokens"] == 0
        assert summary["by_agent"] == {}


class TestSupervisorLedgerInstrumentation:
    """Verifies the ReAct Supervisor's decide_next_step() writes a ledger entry."""

    @pytest.mark.asyncio
    async def test_decide_next_step_records_ledger_entry(self):
        mock_decision = SupervisorDecision(
            thought="Need to gather more evidence on the suspicious host.",
            action="gather_evidence",
            target_entities=["HOST-001"],
            target_skills=["edr-process-tree"],
            specific_goal="Collect process execution history for HOST-001",
        )

        mock_structured_llm = MagicMock()
        mock_structured_llm.ainvoke = AsyncMock(return_value=mock_decision)
        mock_chat = MagicMock()
        mock_chat.with_structured_output.return_value = mock_structured_llm

        context = InvestigationContext(
            alert_data={"alert_id": "alert-ledger-test-1", "computer_name": "HOST-001"},
        )
        context.entities = [{"type": "host", "id": "HOST-001"}]

        supervisor = SupervisorAgent()

        with patch("backend.services.supervisor.get_llm", return_value=mock_chat):
            from backend.services.investigation_ledger import investigation_ledger
            investigation_ledger.clear("alert-ledger-test-1")

            decision = await supervisor.decide_next_step(context)

            assert decision.action == "gather_evidence"

            entries = investigation_ledger.replay("alert-ledger-test-1")
            assert len(entries) == 1
            entry = entries[0]
            assert entry.agent_name == "supervisor_agent"
            assert entry.phase == "supervisor"
            assert entry.decision["action"] == "gather_evidence"
            assert entry.prompt_hash == hashlib.sha256(entry.prompt_sent.encode("utf-8")).hexdigest()
            assert "edr-process-tree" in entry.skills_invoked

            investigation_ledger.clear("alert-ledger-test-1")
