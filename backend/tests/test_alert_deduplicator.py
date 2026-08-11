"""Tests for alert deduplication."""

import pytest
from datetime import datetime
from backend.models.alert import NormalizedAlert, AlertSeverity, AlertSource, AlertStatus
from backend.services.alert_normalizer import CrowdStrikeNormalizer
from backend.services.alert_deduplicator import AlertDeduplicator


@pytest.fixture
def deduplicator():
    """Create a deduplicator instance."""
    return AlertDeduplicator(window_seconds=3600)


@pytest.fixture
def sample_alert():
    """Create a sample normalized alert."""
    normalizer = CrowdStrikeNormalizer()
    raw = {
        'timestamp': int(datetime.utcnow().timestamp() * 1000),
        'name': 'Test Alert',
        'severity': 3,
        'event_type': 'process_execution',
        'user_id': 'user1',
        'user_name': 'User One',
        'computer_name': 'HOST-001',
        'host_id': 'host1',
        'local_ip': '192.168.1.100',
    }
    result = normalizer.normalize(raw)
    return result.normalized_alert


def test_deduplication_first_alert(deduplicator, sample_alert):
    """Test first alert is not a duplicate."""
    result = deduplicator.deduplicate(sample_alert)
    
    assert not result.is_duplicate
    assert result.occurrence_count == 1
    assert result.parent_alert_id is None


def test_deduplication_duplicate_alert(deduplicator, sample_alert):
    """Test duplicate alert is detected."""
    # Ingest first alert
    result1 = deduplicator.deduplicate(sample_alert)
    assert not result1.is_duplicate
    
    # Create similar alert
    sample_alert.alert_id = "different-id"
    sample_alert.timestamp_received = datetime.utcnow().isoformat() + 'Z'
    
    # Ingest duplicate
    result2 = deduplicator.deduplicate(sample_alert)
    
    assert result2.is_duplicate
    assert result2.occurrence_count == 2
    assert result2.parent_alert_id == result1.normalized_alert.alert_id


def test_deduplication_severity_merge(deduplicator, sample_alert):
    """Test severity is upgraded on duplicate."""
    # First alert: medium severity
    sample_alert.severity = AlertSeverity.MEDIUM
    result1 = deduplicator.deduplicate(sample_alert)
    
    assert result1.normalized_alert.severity == AlertSeverity.MEDIUM
    
    # Duplicate with higher severity
    sample_alert.alert_id = "dup-high"
    sample_alert.severity = AlertSeverity.HIGH
    result2 = deduplicator.deduplicate(sample_alert)
    
    # Parent should now have HIGH severity
    assert result2.normalized_alert.severity == AlertSeverity.HIGH


def test_deduplication_entity_merge(deduplicator, sample_alert):
    """Test primary entities are merged on duplicate."""
    # First alert with partial entities
    sample_alert.primary_entities = {
        'user': {'id': 'user1', 'name': 'User One'},
        'host': {'hostname': 'HOST-001'}
    }
    result1 = deduplicator.deduplicate(sample_alert)
    
    # Duplicate with additional entity
    sample_alert.alert_id = "dup-entity"
    sample_alert.primary_entities = {
        'user': {'id': 'user1', 'name': 'User One'},
        'host': {'hostname': 'HOST-001'},
        'ip': '203.0.113.5'
    }
    result2 = deduplicator.deduplicate(sample_alert)
    
    # Parent should now have IP entity
    assert 'ip' in result2.normalized_alert.primary_entities


def test_deduplication_cleanup(deduplicator, sample_alert):
    """Test cleanup of expired alerts."""
    # Ingest an alert
    result1 = deduplicator.deduplicate(sample_alert)
    assert deduplicator.get_alert_count() == 1
    
    # Temporarily set window to 0 to expire all
    deduplicator.window_seconds = 0
    
    # Cleanup should remove the alert
    cleaned = deduplicator.cleanup_expired()
    assert cleaned == 1
    assert deduplicator.get_alert_count() == 0


def test_deduplicator_clear(deduplicator, sample_alert):
    """Test clearing deduplicator state."""
    deduplicator.deduplicate(sample_alert)
    assert deduplicator.get_alert_count() == 1
    
    deduplicator.clear()
    assert deduplicator.get_alert_count() == 0
