"""Alert normalization services for multiple vendors."""

import re
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import uuid4

from backend.models.alert import (
    NormalizedAlert,
    AlertSeverity,
    AlertSource,
    AlertStatus,
    AlertNormalizationResult,
)


class BaseAlertNormalizer(ABC):
    """Base class for vendor-specific alert normalizers."""
    
    def __init__(self, source_name: str, source_system: AlertSource):
        self.source_name = source_name
        self.source_system = source_system
    
    @abstractmethod
    def normalize(self, raw_alert: Dict[str, Any]) -> AlertNormalizationResult:
        """Normalize a raw alert from vendor to standard format."""
        pass
    
    def extract_entities(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract known entities from alert.
        Returns dict with keys like 'user', 'host', 'ip', etc.
        """
        entities = {}
        flattened = self._flatten_dict(raw_alert)
        
        # Entity extraction patterns (case-insensitive)
        patterns = {
            'user': [
                r'user[_\s]*(?:name|id|account|principal)',
                r'samaccount',
                r'username',
                r'uid',
                r'principal',
            ],
            'host': [
                r'(?:source_)?host(?:name)?',
                r'computer(?:_name)?',
                r'device(?:_name)?',
                r'system(?:_name)?',
            ],
            'ip': [
                r'(?:source_)?ip(?:_address)?',
                r'remote_ip',
                r'dest(?:_ip)?',
                r'src_?ip',
            ],
            'domain': [
                r'domain(?:_name)?',
                r'fqdn',
                r'active_directory_domain',
            ],
            'process': [
                r'process(?:_name)?',
                r'command(?:_line)?',
                r'executable',
            ],
            'hash': [
                r'(?:file_)?hash',
                r'sha256',
                r'md5',
            ]
        }
        
        for key, value in flattened.items():
            if not value or not isinstance(value, str):
                continue
            
            key_lower = key.lower()
            for entity_type, regex_list in patterns.items():
                if any(self._regex_match(pattern, key_lower) for pattern in regex_list):
                    if self._is_valid_entity(entity_type, value):
                        if entity_type not in entities:
                            entities[entity_type] = value
                        break
        
        return entities
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary structure."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, (list, tuple)):
                # Skip collections for now
                continue
            else:
                items.append((new_key, str(v)))
        return dict(items)
    
    @staticmethod
    def _regex_match(pattern: str, text: str) -> bool:
        """Check if regex pattern matches text."""
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except re.error:
            return False
    
    @staticmethod
    def _is_valid_entity(entity_type: str, value: str) -> bool:
        """Validate if value is valid for entity type."""
        if not value or len(value.strip()) < 2:
            return False
        
        validators = {
            'ip': lambda v: BaseAlertNormalizer._is_valid_ip(v),
            'domain': lambda v: '.' in v and not any(c in v for c in ['@', '/', '\\']),
            'hash': lambda v: len(v) in [32, 40, 64],  # MD5, SHA1, SHA256
        }
        
        if entity_type in validators:
            return validators[entity_type](value)
        
        return True
    
    @staticmethod
    def _is_valid_ip(ip_str: str) -> bool:
        """Validate IPv4 or IPv6 address."""
        # Simple IPv4 check
        parts = ip_str.split('.')
        if len(parts) == 4:
            return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        # IPv6 has colons
        return ':' in ip_str


class CrowdStrikeNormalizer(BaseAlertNormalizer):
    """CrowdStrike EDR alert normalization."""
    
    def __init__(self):
        super().__init__("CrowdStrike", AlertSource.EDR)
        self.severity_map = {
            5: AlertSeverity.CRITICAL,
            4: AlertSeverity.HIGH,
            3: AlertSeverity.MEDIUM,
            2: AlertSeverity.LOW,
            1: AlertSeverity.INFORMATIONAL,
        }
        self.tactic_map = {
            'process_execution': 'execution',
            'dns_query': 'discovery',
            'network_connection': 'command_and_control',
            'registry_operation': 'persistence',
            'file_write': 'discovery',
            'privilege_escalation': 'privilege_escalation',
            'lateral_movement': 'lateral_movement',
            'authentication': 'credential_access',
            'defense_evasion': 'defense_evasion',
        }
    
    def normalize(self, raw_alert: Dict[str, Any]) -> AlertNormalizationResult:
        """Normalize CrowdStrike alert."""
        try:
            # Extract timestamp
            timestamp_ms = raw_alert.get('timestamp', int(datetime.utcnow().timestamp() * 1000))
            if isinstance(timestamp_ms, (int, float)):
                timestamp = datetime.utcfromtimestamp(timestamp_ms / 1000).isoformat() + 'Z'
            else:
                timestamp = raw_alert.get('timestamp', datetime.utcnow().isoformat() + 'Z')
            
            # Map severity
            severity = self.severity_map.get(
                raw_alert.get('severity', 3),
                AlertSeverity.MEDIUM
            )
            
            # Map event type to MITRE tactic
            event_type = raw_alert.get('event_type', 'unknown')
            mitre_tactic = self.tactic_map.get(event_type, 'discovery')
            
            # Extract entities
            entities = self.extract_entities(raw_alert)
            
            primary_entities = {
                'user': {
                    'id': raw_alert.get('user_id'),
                    'name': raw_alert.get('user_name'),
                    'email': raw_alert.get('email')
                },
                'host': {
                    'id': raw_alert.get('host_id'),
                    'hostname': raw_alert.get('computer_name'),
                    'ip_addresses': [raw_alert.get('local_ip')] if raw_alert.get('local_ip') else []
                },
                'process': {
                    'name': raw_alert.get('process_name'),
                    'path': raw_alert.get('process_path'),
                    'hash': raw_alert.get('process_md5'),
                    'command_line': raw_alert.get('command_line')
                },
                'remote_ip': raw_alert.get('remote_ip'),
            }
            
            # Remove None/empty values
            primary_entities = {
                k: v for k, v in primary_entities.items()
                if v and (not isinstance(v, dict) or any(v.values()))
            }
            
            alert_id = str(uuid4())
            normalized = NormalizedAlert(
                alert_id=alert_id,
                correlation_id=str(uuid4()),
                investigation_id=str(uuid4()),
                timestamp_generated=timestamp,
                timestamp_received=datetime.utcnow().isoformat() + 'Z',
                source_system=self.source_system,
                source_name=self.source_name,
                alert_name=raw_alert.get('name', 'Unknown Alert'),
                alert_description=raw_alert.get('description', ''),
                alert_category=mitre_tactic,
                severity=severity,
                confidence=0.85,  # CrowdStrike is high-confidence
                primary_entities=primary_entities,
                raw_alert=raw_alert,
                alert_metadata={
                    'rule_id': raw_alert.get('rule_id'),
                    'rule_name': raw_alert.get('rule_name'),
                    'mitre_techniques': raw_alert.get('mitre_attacks', []),
                    'event_type': event_type,
                }
            )
            
            return AlertNormalizationResult(
                success=True,
                normalized_alert=normalized
            )
        
        except Exception as e:
            return AlertNormalizationResult(
                success=False,
                error=str(e),
                warnings=[f"CrowdStrike normalization failed: {str(e)}"]
            )


class SplunkNormalizer(BaseAlertNormalizer):
    """Splunk SIEM alert normalization."""
    
    def __init__(self):
        super().__init__("Splunk", AlertSource.SIEM)
        self.severity_map = {
            'critical': AlertSeverity.CRITICAL,
            'high': AlertSeverity.HIGH,
            'medium': AlertSeverity.MEDIUM,
            'low': AlertSeverity.LOW,
            'info': AlertSeverity.INFORMATIONAL,
        }
    
    def normalize(self, raw_alert: Dict[str, Any]) -> AlertNormalizationResult:
        """Normalize Splunk alert."""
        try:
            # Extract timestamp
            timestamp_str = raw_alert.get('_time', datetime.utcnow().isoformat() + 'Z')
            if isinstance(timestamp_str, str):
                timestamp = timestamp_str
            else:
                timestamp = datetime.utcfromtimestamp(timestamp_str).isoformat() + 'Z'
            
            # Map severity
            severity_str = str(raw_alert.get('severity', 'medium')).lower()
            severity = self.severity_map.get(severity_str, AlertSeverity.MEDIUM)
            
            # Extract entities
            entities = self.extract_entities(raw_alert)
            
            primary_entities = {
                'user': raw_alert.get('user', entities.get('user')),
                'host': {
                    'hostname': raw_alert.get('host', entities.get('host')),
                    'ip': raw_alert.get('src_ip', entities.get('ip'))
                },
                'ip': raw_alert.get('src_ip', entities.get('ip')),
                'destination_ip': raw_alert.get('dest_ip'),
            }
            
            # Remove None values
            primary_entities = {
                k: v for k, v in primary_entities.items()
                if v and (not isinstance(v, dict) or any(v.values()))
            }
            
            alert_id = str(uuid4())
            normalized = NormalizedAlert(
                alert_id=alert_id,
                correlation_id=str(uuid4()),
                investigation_id=str(uuid4()),
                timestamp_generated=timestamp,
                timestamp_received=datetime.utcnow().isoformat() + 'Z',
                source_system=self.source_system,
                source_name=self.source_name,
                alert_name=raw_alert.get('alert_name', 'Splunk Alert'),
                alert_description=raw_alert.get('description', ''),
                alert_category=raw_alert.get('category', 'discovery'),
                severity=severity,
                confidence=0.80,
                primary_entities=primary_entities,
                raw_alert=raw_alert,
                alert_metadata={
                    'search_name': raw_alert.get('search_name'),
                    'app': raw_alert.get('app'),
                }
            )
            
            return AlertNormalizationResult(
                success=True,
                normalized_alert=normalized
            )
        
        except Exception as e:
            return AlertNormalizationResult(
                success=False,
                error=str(e)
            )


class AlertNormalizerFactory:
    """Factory for creating appropriate normalizer instances."""
    
    _normalizers = {
        'crowdstrike': CrowdStrikeNormalizer,
        'splunk': SplunkNormalizer,
    }
    
    @classmethod
    def create_normalizer(cls, source: str) -> Optional[BaseAlertNormalizer]:
        """Create a normalizer for the given source."""
        source_lower = source.lower()
        normalizer_class = cls._normalizers.get(source_lower)
        if normalizer_class:
            return normalizer_class()
        return None
    
    @classmethod
    def register_normalizer(cls, source: str, normalizer_class: type):
        """Register a new normalizer."""
        cls._normalizers[source.lower()] = normalizer_class
