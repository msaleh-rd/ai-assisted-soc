"""Tests for alert normalization."""

import pytest
from datetime import datetime
from backend.models.alert import NormalizedAlert, AlertSeverity, AlertSource, AlertStatus
from backend.services.alert_normalizer import (
    CrowdStrikeNormalizer,
    SplunkNormalizer,
    AlertNormalizerFactory,
)


@pytest.fixture
def crowdstrike_alert():
    """Sample CrowdStrike alert."""
    return {
        'timestamp': int(datetime.utcnow().timestamp() * 1000),
        'name': 'Suspicious Process Execution',
        'description': 'PowerShell executed unusual child process',
        'severity': 4,
        'event_type': 'process_execution',
        'user_id': 'john.doe',
        'user_name': 'John Doe',
        'computer_name': 'WORKSTATION-001',
        'host_id': 'abc123',
        'local_ip': '192.168.1.100',
        'remote_ip': '203.0.113.5',
        'process_name': 'powershell.exe',
        'process_path': 'C:\\Windows\\System32\\powershell.exe',
        'process_md5': 'abc123def456',
        'command_line': 'powershell.exe -NoProfile -WindowStyle Hidden',
        'rule_id': 'CS-001',
        'rule_name': 'Suspicious PowerShell',
        'mitre_attacks': ['T1059.001']
    }


def test_crowdstrike_normalization(crowdstrike_alert):
    """Test CrowdStrike alert normalization."""
    normalizer = CrowdStrikeNormalizer()
    result = normalizer.normalize(crowdstrike_alert)
    
    assert result.success
    assert result.normalized_alert is not None
    
    alert = result.normalized_alert
    assert alert.source_name == "CrowdStrike"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.alert_category == "execution"
    assert alert.primary_entities['user']['id'] == 'john.doe'
    assert alert.primary_entities['host']['hostname'] == 'WORKSTATION-001'


def test_crowdstrike_entity_extraction(crowdstrike_alert):
    """Test entity extraction from CrowdStrike alert."""
    normalizer = CrowdStrikeNormalizer()
    entities = normalizer.extract_entities(crowdstrike_alert)
    
    assert 'user' in entities
    assert 'host' in entities
    assert 'ip' in entities
    assert entities['ip'] == '203.0.113.5'


def test_splunk_normalization():
    """Test Splunk alert normalization."""
    alert = {
        '_time': datetime.utcnow().isoformat() + 'Z',
        'alert_name': 'Suspicious Login',
        'description': 'User login from unusual location',
        'severity': 'high',
        'user': 'jane.smith',
        'host': 'SERVER-001',
        'src_ip': '10.0.0.50',
        'dest_ip': '203.0.113.100',
        'search_name': 'Detect Suspicious Logins',
        'app': 'Security'
    }
    
    normalizer = SplunkNormalizer()
    result = normalizer.normalize(alert)
    
    assert result.success
    assert result.normalized_alert.source_name == "Splunk"
    assert result.normalized_alert.severity == AlertSeverity.HIGH


def test_normalizer_factory():
    """Test normalizer factory."""
    cs_normalizer = AlertNormalizerFactory.create_normalizer('crowdstrike')
    assert cs_normalizer is not None
    assert isinstance(cs_normalizer, CrowdStrikeNormalizer)
    
    splunk_normalizer = AlertNormalizerFactory.create_normalizer('splunk')
    assert splunk_normalizer is not None
    assert isinstance(splunk_normalizer, SplunkNormalizer)
    
    unknown = AlertNormalizerFactory.create_normalizer('unknown_source')
    assert unknown is None


def test_normalized_alert_serialization(crowdstrike_alert):
    """Test alert serialization/deserialization."""
    normalizer = CrowdStrikeNormalizer()
    result = normalizer.normalize(crowdstrike_alert)
    
    alert = result.normalized_alert
    alert_dict = alert.to_dict()
    
    # Can serialize to dict
    assert isinstance(alert_dict, dict)
    assert alert_dict['source_name'] == 'CrowdStrike'
    assert alert_dict['severity'] == 'high'
    
    # Can deserialize back
    restored = NormalizedAlert.from_dict(alert_dict)
    assert restored.alert_name == alert.alert_name
    assert restored.severity == alert.severity
