"""Integration tests for alert intake service."""

import pytest
import asyncio
from backend.services.alert_intake import AlertIntakeService
from backend.services.alert_normalizer import CrowdStrikeNormalizer
from datetime import datetime


@pytest.fixture
def intake_service():
    """Create alert intake service."""
    return AlertIntakeService()


@pytest.fixture
def crowdstrike_alert():
    """Sample CrowdStrike alert."""
    return {
        'timestamp': int(datetime.utcnow().timestamp() * 1000),
        'name': 'Suspicious Process Execution',
        'description': 'PowerShell executed from unusual location',
        'severity': 4,
        'event_type': 'process_execution',
        'user_id': 'attacker@company.com',
        'user_name': 'Attacker User',
        'computer_name': 'COMPROMISED-HOST',
        'host_id': 'host123',
        'local_ip': '10.0.1.50',
        'remote_ip': '203.0.113.10',
        'process_name': 'powershell.exe',
        'process_path': 'C:\\Windows\\System32\\powershell.exe',
        'command_line': 'powershell.exe -NoProfile -Hidden',
    }


@pytest.mark.asyncio
async def test_single_alert_ingestion(intake_service, crowdstrike_alert):
    """Test ingesting a single alert."""
    result = await intake_service.ingest_alert(crowdstrike_alert, 'crowdstrike')
    
    assert result['status'] == 'accepted'
    assert 'alert_id' in result
    assert 'investigation_id' in result
    assert result['severity'] == 'high'
    assert result['source'] == 'CrowdStrike'


@pytest.mark.asyncio
async def test_batch_alert_ingestion(intake_service):
    """Test batch alert ingestion."""
    alerts = [
        {
            'timestamp': int(datetime.utcnow().timestamp() * 1000),
            'name': f'Alert {i}',
            'severity': 3,
            'event_type': 'process_execution',
            'user_id': f'user{i}',
            'computer_name': f'HOST-{i:03d}',
        }
        for i in range(5)
    ]
    
    results = await intake_service.ingest_alerts_batch(alerts, 'crowdstrike')
    
    assert len(results) == 5
    assert all(r['status'] in ['accepted', 'deduplicated'] for r in results)


@pytest.mark.asyncio
async def test_alert_deduplication(intake_service, crowdstrike_alert):
    """Test that duplicate alerts are detected."""
    # Ingest first alert
    result1 = await intake_service.ingest_alert(crowdstrike_alert, 'crowdstrike')
    assert result1['status'] == 'accepted'
    assert result1['occurrence_count'] == 1
    
    # Ingest duplicate (same key fields)
    result2 = await intake_service.ingest_alert(crowdstrike_alert, 'crowdstrike')
    assert result2['status'] == 'deduplicated'
    assert result2['occurrence_count'] == 2
    assert result2['parent_alert_id'] == result1['alert_id']


@pytest.mark.asyncio
async def test_unknown_source(intake_service):
    """Test handling of unknown alert source."""
    result = await intake_service.ingest_alert({}, 'unknown_source')
    
    assert result['status'] == 'error'
    assert 'Unknown alert source' in result['error']


@pytest.mark.asyncio
async def test_invalid_alert_format(intake_service):
    """Test handling of invalid alert format."""
    result = await intake_service.ingest_alert({'invalid': 'data'}, 'crowdstrike')
    
    # Should still process but may have warnings
    assert result['status'] in ['error', 'accepted', 'deduplicated']


def test_pending_alerts_queue(intake_service, crowdstrike_alert):
    """Test pending alerts queue."""
    async def run_test():
        # Ingest alert
        await intake_service.ingest_alert(crowdstrike_alert, 'crowdstrike')
        
        # Get pending alerts
        pending = intake_service.get_pending_alerts()
        assert len(pending) == 1
        assert pending[0].alert_name == 'Suspicious Process Execution'
        
        # Queue should be cleared
        pending2 = intake_service.get_pending_alerts()
        assert len(pending2) == 0
    
    asyncio.run(run_test())


def test_service_stats(intake_service):
    """Test service statistics."""
    stats = intake_service.get_stats()
    
    assert 'tracked_alerts' in stats
    assert 'pending_evidence_collection' in stats
    assert 'dedup_window_seconds' in stats
    assert stats['tracked_alerts'] >= 0
    assert stats['dedup_window_seconds'] == 1800
