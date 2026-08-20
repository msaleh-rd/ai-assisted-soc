import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

from backend.services.investigation_context import InvestigationContext
from backend.services.orchestrator import CompressionAgent, RCAAnalystAgent
from backend.services.llm_client import RCAOutput


@pytest.mark.asyncio
async def test_compression_agent_real_pipeline():
    """Verify CompressionAgent runs real 7-stage correlation without synthetic mock formulas."""
    context = InvestigationContext(
        alert_data={
            "alert_id": "test_alert_101",
            "computer_name": "linuxshare",
            "ip_address": "192.168.100.50",
            "user_name": "root",
            "file_name": "donotcry",
            "severity": 5,
            "description": "Ransomware execution detected",
            "timestamp": "2026-08-20T12:00:00Z"
        },
        entities=[
            {"id": "root", "type": "user"},
            {"id": "linuxshare", "type": "host"},
            {"id": "192.42.1.174", "type": "ip"},
            {"id": "donotcry", "type": "file"},
        ],
        entity_graph={
            "user:root": {"type": "user", "id": "root", "risk_score": 0.8},
            "host:linuxshare": {"type": "host", "id": "linuxshare", "risk_score": 0.9},
            "ip:192.42.1.174": {"type": "ip", "id": "192.42.1.174", "risk_score": 0.85},
            "file:donotcry": {"type": "file", "id": "donotcry", "risk_score": 0.95},
        },
        relationships=[
            {"source": "user:root", "target": "host:linuxshare", "type": "logged_into"},
            {"source": "file:donotcry", "target": "host:linuxshare", "type": "runs_on"},
            {"source": "host:linuxshare", "target": "ip:192.42.1.174", "type": "connected_to"},
        ],
        classification="malware_execution",
        severity="Critical"
    )

    agent = CompressionAgent()
    report = await agent.execute(inputs={}, context=context)

    # Validate agent report
    assert report.status.value == "completed"
    assert report.findings["original_events"] > 0
    assert report.findings["compressed_events"] > 0
    assert "compression_ratio" in report.findings
    assert len(report.findings["stages"]) == 7

    # Validate blackboard context
    assert "timeline" in context.compressed_events
    assert len(context.compressed_events["timeline"]) > 0
    assert "risk_score" in context.compressed_events
    assert "confidence" in context.compressed_events


@pytest.mark.asyncio
async def test_rca_hybrid_causal_analyzer():
    """Verify RCAAnalystAgent builds topology DiGraph and runs sx_truerca CausalAnalyzer."""
    context = InvestigationContext(
        alert_data={
            "alert_id": "test_alert_102",
            "computer_name": "linuxshare",
            "ip_address": "192.168.100.50",
            "user_name": "root",
            "file_name": "donotcry",
            "severity": 5,
            "description": "Ransomware execution detected",
            "timestamp": "2026-08-20T12:00:00Z"
        },
        entities=[
            {"id": "root", "type": "user"},
            {"id": "linuxshare", "type": "host"},
            {"id": "192.42.1.174", "type": "ip"},
            {"id": "donotcry", "type": "file"},
        ],
        entity_graph={
            "user:root": {"type": "user", "id": "root", "risk_score": 0.8},
            "host:linuxshare": {"type": "host", "id": "linuxshare", "risk_score": 0.9},
            "ip:192.42.1.174": {"type": "ip", "id": "192.42.1.174", "risk_score": 0.85},
            "file:donotcry": {"type": "file", "id": "donotcry", "risk_score": 0.95},
        },
        relationships=[
            {"source": "user:root", "target": "host:linuxshare", "type": "logged_into"},
            {"source": "file:donotcry", "target": "host:linuxshare", "type": "runs_on"},
            {"source": "host:linuxshare", "target": "ip:192.42.1.174", "type": "connected_to"},
        ],
        compressed_events={
            "timeline": [
                {"entity": "file:donotcry", "timestamp": "2026-08-20T11:59:00Z", "risk_score": 0.95, "event_type": "file_execution"},
                {"entity": "host:linuxshare", "timestamp": "2026-08-20T12:00:00Z", "risk_score": 0.9, "event_type": "security_alert"},
            ]
        },
        classification="malware_execution",
        severity="Critical"
    )

    agent = RCAAnalystAgent()

    # Mock the LLM call to verify pure causal orchestration & prompt synthesis
    mock_rca_output = RCAOutput(
        chain_of_thought_verification="The causal analyzer points to file:donotcry as the root cause due to early execution timeline and highest anomaly score.",
        root_cause="Execution of donotcry ransomware binary on linuxshare by root user.",
        attack_phases=[
            "Ingress of malicious binary donotcry from 192.42.1.174",
            "Execution under root privilege on linuxshare",
            "File encryption commenced"
        ],
        blast_radius=4,
        confidence=0.92
    )

    with patch("backend.services.llm_client.get_llm") as mock_get_llm:
        mock_chat = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=mock_rca_output)
        mock_chat.with_structured_output.return_value = mock_structured
        mock_get_llm.return_value = mock_chat

        report = await agent.execute(inputs={}, context=context)

        # Validate findings
        assert report.status.value == "completed"
        assert report.findings["root_cause"] == "Execution of donotcry ransomware binary on linuxshare by root user."
        assert len(report.findings["structural_causal_candidates"]) > 0

        # Validate causal candidate output
        top_candidate = report.findings["structural_causal_candidates"][0]
        assert "candidate_entity" in top_candidate
        assert "causal_score" in top_candidate
        assert "reasoning" in top_candidate

        # Validate context integration
        assert len(context.causal_candidates) > 0
        assert context.rca_findings["confidence_score"] == 0.92
