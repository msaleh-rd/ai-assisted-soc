"""Tests for the Autonomous ReAct Investigation Supervisor and Dual-Mode Execution."""

import pytest
import asyncio
from typing import Dict, Any

from backend.services.investigation_context import InvestigationContext
from backend.services.supervisor import SupervisorAgent
from backend.services.llm_client import SupervisorDecision
from backend.services.orchestrator import OrchestratorAgent
from backend.services.temporal_workflows import supervisor_activity


SAMPLE_ALERT: Dict[str, Any] = {
    "alert_id": "test_ransomware_react_001",
    "description": "Ransomware execution detected: install.sh downloaded from 192.42.1.174:8888, encrypting files in /media/data/Images",
    "severity": 5,
    "severity_name": "Critical",
    "user_name": "root",
    "computer_name": "linuxshare",
    "ip_address": "192.168.100.50",
    "file_name": "donotcry",
    "file_path": "/opt/donotcry",
    "timestamp": "2026-08-24T09:52:29.446Z",
    "source": "Suricata / Wazuh",
}


@pytest.mark.asyncio
async def test_supervisor_heuristic_fallback_progression():
    """Verify that fallback decisions logically progress through the investigation lifecycle."""
    supervisor = SupervisorAgent()
    context = InvestigationContext(alert_data=SAMPLE_ALERT, use_ai_planner=True)
    context.add_entity("linuxshare", "host")
    context.add_entity("root", "user")

    # Step 1: No evidence yet -> Should gather evidence
    d1 = supervisor._heuristic_fallback_decision(context)
    assert d1.action == "gather_evidence"
    assert "linuxshare" in d1.target_entities

    # Step 2: Evidence exists but no compressed events -> Should compress
    context.entity_graph = {"host:linuxshare": {"risk_score": 0.8}}
    d2 = supervisor._heuristic_fallback_decision(context)
    assert d2.action == "compress_events"

    # Step 3: Compressed events exist -> Should perform RCA
    context.compressed_events = {"timeline": [{"action": "curl download", "risk_score": 0.9}]}
    d3 = supervisor._heuristic_fallback_decision(context)
    assert d3.action == "perform_rca"

    # Step 4: High confidence RCA exists -> Finalize response
    context.rca_findings = {"root_cause": "donotcry ransomware executed", "confidence_score": 0.95}
    d4 = supervisor._heuristic_fallback_decision(context)
    assert d4.action == "finalize_response"


@pytest.mark.asyncio
async def test_supervisor_decision_validation_and_sanitization():
    """Verify that decisions are sanitized (e.g. populating missing targets, enforcing prerequisite order)."""
    supervisor = SupervisorAgent()
    context = InvestigationContext(alert_data=SAMPLE_ALERT, use_ai_planner=True)
    context.add_entity("linuxshare", "host")
    context.add_entity("192.168.100.50", "ip")

    # Test missing targets on gather_evidence
    raw_decision = SupervisorDecision(
        thought="Need more evidence",
        action="gather_evidence",
        target_entities=[],
        specific_goal="Collect all logs"
    )
    sanitized = supervisor._validate_and_sanitize_decision(raw_decision, context)
    assert len(sanitized.target_entities) == 2
    assert "linuxshare" in sanitized.target_entities

    # Test RCA requested before compression
    raw_rca = SupervisorDecision(
        thought="Perform RCA immediately",
        action="perform_rca",
        specific_goal="Analyze cause"
    )
    sanitized_rca = supervisor._validate_and_sanitize_decision(raw_rca, context)
    assert sanitized_rca.action == "compress_events"


@pytest.mark.asyncio
async def test_supervisor_pivot_entity_registration():
    """Verify that lateral movement pivots detected in decisions or logs are dynamically registered."""
    context = InvestigationContext(alert_data=SAMPLE_ALERT, use_ai_planner=True)
    context.add_entity("linuxshare", "host")

    # Add new pivot IP
    is_new = context.add_entity("192.42.1.174", "ip", is_pivot=True)
    assert is_new is True
    assert len(context.pivot_entities) == 1
    assert context.pivot_entities[0]["id"] == "192.42.1.174"

    # Adding again should be idempotent
    is_new_again = context.add_entity("192.42.1.174", "ip", is_pivot=True)
    assert is_new_again is False
    assert len(context.pivot_entities) == 1


@pytest.mark.asyncio
async def test_temporal_supervisor_activity():
    """Verify that supervisor_activity executes durably and updates context."""
    context = InvestigationContext(alert_data=SAMPLE_ALERT, use_ai_planner=True)
    context.add_entity("linuxshare", "host")
    context.add_entity("root", "user")

    result = await supervisor_activity(context.to_dict())
    assert "decision" in result
    assert "context" in result
    assert result["decision"]["action"] in [
        "gather_evidence", "discover_network", "compress_events", "perform_rca", "terminate_benign", "finalize_response"
    ]
    assert len(result["context"]["supervisor_history"]) >= 1


@pytest.mark.asyncio
async def test_dual_mode_orchestrator_static_stream():
    """Verify static deterministic pipeline execution mode (use_ai_planner=False)."""
    orchestrator = OrchestratorAgent()
    events = []
    
    async for raw_evt in orchestrator.execute_stream("Investigate Alert", SAMPLE_ALERT, use_ai_planner=False):
        events.append(raw_evt)

    assert len(events) > 0
    # Should start with deterministic_static mode
    combined = "".join(events)
    assert "deterministic_static" in combined
    assert "run_complete" in combined
    assert "completed" in combined


@pytest.mark.asyncio
async def test_dual_mode_orchestrator_react_supervisor_stream():
    """Verify autonomous ReAct Supervisor pipeline execution mode (use_ai_planner=True)."""
    orchestrator = OrchestratorAgent()
    events = []
    
    async for raw_evt in orchestrator.execute_stream("Investigate Alert", SAMPLE_ALERT, use_ai_planner=True):
        events.append(raw_evt)

    assert len(events) > 0
    combined = "".join(events)
    assert "autonomous_react_supervisor" in combined
    assert "supervisor_thought" in combined
    assert "run_complete" in combined
