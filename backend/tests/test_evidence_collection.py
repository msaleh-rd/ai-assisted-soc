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
