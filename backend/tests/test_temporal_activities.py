"""Test Temporal Activities directly to ensure no missing variables or runtime errors."""

import pytest
import asyncio
from backend.services.investigation_context import InvestigationContext
from backend.services.temporal_workflows import (
    triage_activity,
    evidence_activity,
    discovery_activity,
    compression_activity,
    rca_activity,
    response_activity,
)

@pytest.mark.asyncio
async def test_temporal_activities_direct_execution():
    alert_data = {
        "alert_id": "test_alert_temporal_001",
        "computer_name": "linuxshare",
        "file_name": "donotcry",
        "file_path": "/media/data/Images/donotcry",
        "ip_address": "192.168.100.50",
        "severity": 5,
        "severity_name": "Critical",
        "source": "Suricata IDS / Wazuh",
        "timestamp": "2026-08-23T19:08:32.407Z",
        "user_name": "root",
        "description": "Ransomware execution test"
    }
    
    context = InvestigationContext(alert_data=alert_data)
    
    # 1. Triage
    triage_res = await triage_activity(context.to_dict())
    assert triage_res["report"]["status"] == "completed"
    ctx_dict = triage_res["context"]
    
    # 2. Evidence
    evidence_res = await evidence_activity(ctx_dict)
    assert evidence_res["report"]["status"] == "completed"
    ctx_dict = evidence_res["context"]
    
    # 3. Discovery
    discovery_res = await discovery_activity(ctx_dict)
    assert discovery_res["report"]["status"] == "completed"
    ctx_dict = discovery_res["context"]
    
    # 4. Compression
    compression_res = await compression_activity(ctx_dict)
    assert compression_res["report"]["status"] == "completed"
    assert compression_res["report"]["findings"]["compressed_events"] > 0
    ctx_dict = compression_res["context"]
    
    # 5. RCA
    rca_res = await rca_activity(ctx_dict)
    assert rca_res["report"]["status"] == "completed"
    ctx_dict = rca_res["context"]
    
    # 6. Response
    response_res = await response_activity(ctx_dict)
    assert response_res["report"]["status"] == "completed"
    assert len(response_res["report"]["findings"]["actions_recommended"]) > 0
