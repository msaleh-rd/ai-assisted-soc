"""Tests for evidence collection."""

import pytest
import asyncio
from backend.models.alert import NormalizedAlert, AlertSeverity, AlertSource
from backend.services.evidence_collection import (
    EvidenceCollectorRegistry,
    EvidenceCollectionOrchestrator,
    UserEvidenceCollector,
)
from backend.models.entities import EntityType


@pytest.fixture
def sample_alert():
    """Create sample alert for testing."""
    alert = NormalizedAlert(
        alert_id='test-alert-1',
        correlation_id='corr-1',
        investigation_id='inv-1',
        timestamp_generated='2024-08-10T10:00:00Z',
        timestamp_received='2024-08-10T10:00:01Z',
        source_system=AlertSource.EDR,
        source_name='CrowdStrike',
        alert_name='Test Alert',
        alert_description='Test',
        alert_category='execution',
        severity=AlertSeverity.HIGH,
        confidence=0.85,
        primary_entities={
            'user': {'id': 'user1', 'name': 'Test User'},
            'host': {'id': 'host1', 'hostname': 'TEST-HOST'},
            'ip': '192.168.1.100'
        },
        raw_alert={},
    )
    return alert


def test_user_evidence_collector():
    """Test user evidence collector."""
    collector = UserEvidenceCollector()
    
    async def run_test():
        evidence = await collector.collect('user1', {})
        assert 'enrichment_data' in evidence
        assert 'threat_intel' in evidence
        assert 'risk_score' in evidence
        assert evidence['enrichment_data']['email'] == 'user1@company.com'
    
    asyncio.run(run_test())


def test_evidence_collector_registry():
    """Test evidence collector registry."""
    registry = EvidenceCollectorRegistry()
    
    user_collector = registry.get_collector(EntityType.USER)
    assert user_collector is not None
    assert user_collector.entity_type == EntityType.USER
    
    host_collector = registry.get_collector(EntityType.HOST)
    assert host_collector is not None
    assert host_collector.entity_type == EntityType.HOST


def test_entity_extraction_from_alert(sample_alert):
    """Test extracting entities from alert."""
    orchestrator = EvidenceCollectionOrchestrator()
    entities = orchestrator._extract_entities_from_alert(sample_alert)
    
    assert len(entities) >= 3  # user, host, ip
    
    entity_types = [e.entity_type for e in entities]
    assert EntityType.USER in entity_types
    assert EntityType.HOST in entity_types
    assert EntityType.IP_ADDRESS in entity_types


def test_host_evidence_collector():
    """Test host evidence collector correctly profiles Linux vs Windows."""
    from backend.services.evidence_collection import HostEvidenceCollector
    collector = HostEvidenceCollector()
    
    async def run_test():
        evidence = await collector.collect('linuxshare', {})
        assert 'enrichment_data' in evidence
        assert 'Linux' in evidence['enrichment_data']['os']
        assert evidence['enrichment_data']['is_server'] is True
        
        evidence_win = await collector.collect('workstation-pc', {})
        assert 'Windows' in evidence_win['enrichment_data']['os']
    
    asyncio.run(run_test())


def test_ip_evidence_collector():
    """Test IP evidence collector identifies internal vs external C2."""
    from backend.services.evidence_collection import IPAddressEvidenceCollector
    collector = IPAddressEvidenceCollector()
    
    async def run_test():
        evidence_internal = await collector.collect('192.168.100.50', {})
        assert evidence_internal['enrichment_data']['is_internal'] is True
        assert evidence_internal['threat_intel']['malware_c2'] is False
        
        evidence_external = await collector.collect('192.42.1.174', {})
        assert evidence_external['enrichment_data']['is_internal'] is False
        assert evidence_external['risk_score'] >= 0.8
        assert evidence_external['threat_intel']['malware_c2'] is True
    
    asyncio.run(run_test())


def test_file_evidence_collector():
    """Test file evidence collector flags malware binaries without mock Microsoft signatures."""
    from backend.services.evidence_collection import FileEvidenceCollector
    collector = FileEvidenceCollector()
    
    async def run_test():
        evidence_malware = await collector.collect('/tmp/donotcry', {})
        assert evidence_malware['threat_intel']['signed'] is False
        assert evidence_malware['threat_intel']['known_malware'] is True
        assert evidence_malware['risk_score'] >= 0.9
        
        evidence_system = await collector.collect('/bin/ls', {})
        assert evidence_system['threat_intel']['signed'] is True
        assert evidence_system['risk_score'] <= 0.1
    
    asyncio.run(run_test())


def test_process_evidence_collector():
    """Test process evidence collector distinguishes threats from daemons."""
    from backend.services.evidence_collection import ProcessEvidenceCollector
    collector = ProcessEvidenceCollector()
    
    async def run_test():
        evidence_malware = await collector.collect('donotcry', {})
        assert evidence_malware['threat_intel']['known_malware'] is True
        assert evidence_malware['risk_score'] >= 0.9
        
        evidence_daemon = await collector.collect('systemd', {})
        assert evidence_daemon['threat_intel']['known_malware'] is False
        assert evidence_daemon['risk_score'] <= 0.1
    
    asyncio.run(run_test())


def test_evidence_collection_orchestrator(sample_alert):
    """Test evidence collection orchestration."""
    orchestrator = EvidenceCollectionOrchestrator()
    
    async def run_test():
        context = await orchestrator.collect_for_alert(sample_alert, max_depth=1)
        
        assert 'investigation_id' in context
        assert context['investigation_id'] == sample_alert.investigation_id
        assert 'entities' in context
        assert 'relationships' in context
        assert 'enrichment_data' in context
        
        # Should have extracted entities
        assert len(context['entities']) > 0
    
    asyncio.run(run_test())
