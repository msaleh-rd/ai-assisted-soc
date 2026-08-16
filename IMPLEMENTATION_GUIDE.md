# AI-Native SOC Platform - Implementation Guide

## Part 1: Alert Normalization Implementation

### 1.1 Alert Normalization Service (Python)

```python
import json
import hashlib
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from uuid import uuid4
from abc import ABC, abstractmethod

# Core Schemas
@dataclass
class Entity:
    entity_type: str  # 'user', 'host', 'process', 'ip', 'domain', 'file'
    entity_id: str
    entity_name: Optional[str] = None

@dataclass
class NormalizedAlert:
    alert_id: str
    correlation_id: str
    timestamp_generated: str
    timestamp_received: str
    source_system: str  # 'siem', 'xdr', 'edr', 'cloud', 'iam'
    source_name: str
    alert_name: str
    alert_description: str
    alert_category: str  # MITRE ATT&CK tactic
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float  # 0.0-1.0
    primary_entities: Dict[str, Any]
    raw_alert: Dict[str, Any]
    alert_metadata: Dict[str, Any]
    occurrence_count: int = 1
    last_occurrence: Optional[str] = None

class AlertNormalizer(ABC):
    """Base class for vendor-specific alert normalization"""
    
    @abstractmethod
    def normalize(self, raw_alert: Dict[str, Any]) -> NormalizedAlert:
        pass
    
    def extract_entities(self, raw_alert: Dict[str, Any]) -> Dict[str, Entity]:
        """Extract known entity patterns from alert"""
        entities = {}
        
        # Entity extraction patterns (vendor-agnostic)
        patterns = {
            'user': [
                r'user[_\s]*(?:name|id|account)',
                r'samaccount',
                r'username',
                r'uid'
            ],
            'host': [
                r'(?:source_)?host(?:name)?',
                r'computer(?:_name)?',
                r'device(?:_name)?',
                r'system(?:_name)?'
            ],
            'ip': [
                r'(?:source_)?ip(?:_address)?',
                r'remote_ip',
                r'dest(?:_ip)?'
            ],
            'domain': [
                r'domain(?:_name)?',
                r'fqdn'
            ],
            'process': [
                r'process(?:_name)?',
                r'command(?:_line)?',
                r'executable'
            ],
            'file_hash': [
                r'(?:file_)?hash',
                r'sha256',
                r'md5'
            ]
        }
        
        # Flatten alert to key-value pairs and match patterns
        flattened = self._flatten_dict(raw_alert)
        
        for key, value in flattened.items():
            for entity_type, regex_list in patterns.items():
                if any(self._regex_match(pattern, key.lower()) for pattern in regex_list):
                    if value and self._is_valid_entity(entity_type, str(value)):
                        entities[entity_type] = Entity(
                            entity_type=entity_type,
                            entity_id=str(value),
                            entity_name=str(value)
                        )
                        break
        
        return entities
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    @staticmethod
    def _regex_match(pattern: str, text: str) -> bool:
        import re
        return bool(re.search(pattern, text))
    
    @staticmethod
    def _is_valid_entity(entity_type: str, value: str) -> bool:
        """Basic validation for entity types"""
        if not value or len(value) < 2:
            return False
        
        validators = {
            'ip': lambda v: len(v.split('.')) == 4 or ':' in v,  # IPv4 or IPv6
            'domain': lambda v: '.' in v and not any(c in v for c in ['@', '/']),
            'email': lambda v: '@' in v and '.' in v,
            'file_hash': lambda v: len(v) in [32, 40, 64],  # MD5, SHA1, SHA256
        }
        
        if entity_type in validators:
            return validators[entity_type](value)
        
        return True


class CrowdStrikeNormalizer(AlertNormalizer):
    """CrowdStrike EDR alert normalization"""
    
    def normalize(self, raw_alert: Dict[str, Any]) -> NormalizedAlert:
        # Extract timestamp
        timestamp_ms = raw_alert.get('timestamp', int(datetime.now().timestamp() * 1000))
        timestamp = datetime.fromtimestamp(timestamp_ms / 1000).isoformat() + 'Z'
        
        # Map CrowdStrike severity to standard
        cs_severity_map = {
            5: 'critical',
            4: 'high',
            3: 'medium',
            2: 'low',
            1: 'informational'
        }
        severity = cs_severity_map.get(raw_alert.get('severity', 3), 'medium')
        
        # Map CrowdStrike event type to MITRE tactic
        event_type = raw_alert.get('event_type', '')
        mitre_tactic = self._map_cs_event_to_mitre(event_type)
        
        # Extract entities
        primary_entities = {
            'user': {
                'id': raw_alert.get('user_id'),
                'name': raw_alert.get('user_name'),
                'email': raw_alert.get('email')
            },
            'host': {
                'id': raw_alert.get('host_id'),
                'hostname': raw_alert.get('computer_name'),
                'ip_addresses': [raw_alert.get('local_ip')] if raw_alert.get('local_ip') else None
            },
            'process': {
                'name': raw_alert.get('process_name'),
                'path': raw_alert.get('process_path'),
                'hash_sha256': raw_alert.get('process_md5'),  # CrowdStrike may provide MD5
                'command_line': raw_alert.get('command_line')
            },
            'ip_address': raw_alert.get('remote_ip')
        }
        
        # Remove None values
        primary_entities = {k: v for k, v in primary_entities.items() if v}
        
        # Create normalized alert
        alert_id = str(uuid4())
        normalized = NormalizedAlert(
            alert_id=alert_id,
            correlation_id=str(uuid4()),
            timestamp_generated=timestamp,
            timestamp_received=datetime.now().isoformat() + 'Z',
            source_system='edr',
            source_name='CrowdStrike',
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
                'mitre_tactics': [mitre_tactic],
                'mitre_techniques': raw_alert.get('mitre_attacks', [])
            }
        )
        
        return normalized
    
    @staticmethod
    def _map_cs_event_to_mitre(event_type: str) -> str:
        """Map CrowdStrike event types to MITRE ATT&CK tactics"""
        mapping = {
            'process_execution': 'execution',
            'dns_query': 'discovery',
            'network_connection': 'command_and_control',
            'registry_operation': 'persistence',
            'file_write': 'discovery',
            'privilege_escalation': 'privilege_escalation',
            'lateral_movement': 'lateral_movement',
            'authentication': 'credential_access'
        }
        return mapping.get(event_type.lower(), 'discovery')


class AlertDeduplicator:
    """Deduplicates alerts within a time window"""
    
    def __init__(self, window_seconds: int = 1800):  # 30 minute default
        self.window_seconds = window_seconds
        self.recent_alerts = {}  # Hash -> Alert
    
    def deduplicate(self, alert: NormalizedAlert) -> tuple[NormalizedAlert, bool]:
        """
        Returns: (alert, is_duplicate)
        If duplicate, returns existing alert with occurrence count incremented
        """
        # Create fingerprint from key fields
        fingerprint = self._create_fingerprint(alert)
        
        if fingerprint in self.recent_alerts:
            existing = self.recent_alerts[fingerprint]
            existing.occurrence_count += 1
            existing.last_occurrence = alert.timestamp_received
            existing.severity = max(existing.severity, alert.severity,
                                   key=lambda x: ['informational', 'low', 'medium', 'high', 'critical'].index(x))
            return existing, True
        else:
            self.recent_alerts[fingerprint] = alert
            return alert, False
    
    @staticmethod
    def _create_fingerprint(alert: NormalizedAlert) -> str:
        """Create fingerprint for deduplication"""
        key_fields = [
            alert.source_name,
            alert.alert_name,
            str(alert.primary_entities.get('user', {}).get('id', '')),
            str(alert.primary_entities.get('host', {}).get('id', '')),
            str(alert.primary_entities.get('ip_address', ''))
        ]
        
        fingerprint_str = '|'.join(key_fields)
        return hashlib.md5(fingerprint_str.encode()).hexdigest()


class AlertIntakeService:
    """Main service for alert intake and normalization"""
    
    def __init__(self):
        # Normalizers for each vendor
        self.normalizers = {
            'crowdstrike': CrowdStrikeNormalizer(),
            # Add more normalizers for other vendors
        }
        self.deduplicator = AlertDeduplicator(window_seconds=1800)
    
    def ingest_alert(self, raw_alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """
        Main entry point for alert ingestion
        """
        # Select normalizer
        normalizer = self.normalizers.get(source.lower())
        if not normalizer:
            raise ValueError(f"Unknown source: {source}")
        
        # Normalize alert
        normalized_alert = normalizer.normalize(raw_alert)
        
        # Deduplicate
        alert, is_duplicate = self.deduplicator.deduplicate(normalized_alert)
        
        return {
            'status': 'deduplicated' if is_duplicate else 'accepted',
            'alert_id': alert.alert_id,
            'correlation_id': alert.correlation_id,
            'investigation_id': str(uuid4()),  # Assigned during intake
            'occurrence_count': alert.occurrence_count
        }

# Example usage
if __name__ == '__main__':
    service = AlertIntakeService()
    
    # Example raw CrowdStrike alert
    raw_alert = {
        'timestamp': int(datetime.now().timestamp() * 1000),
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
    
    result = service.ingest_alert(raw_alert, 'crowdstrike')
    print(json.dumps(result, indent=2))
```

---

## Part 2: Behavioral Baseline Implementation

### 2.1 Behavioral Anomaly Detection (Python)

```python
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class UserBaseline:
    """User behavioral baseline from historical data"""
    uid: str
    avg_events_per_hour: float
    events_per_hour_std: float
    time_distribution: Dict[int, float]  # Hour -> probability
    typical_actions: Dict[str, float]  # Action -> frequency
    typical_targets: Dict[str, float]  # Target -> frequency
    typical_locations: List[str]  # IP geolocation
    typical_login_hours: Tuple[int, int]  # (start, end) in UTC
    mfa_success_rate: float
    last_updated: str

class BehavioralAnomalyDetector:
    """
    ML-based anomaly detection using Isolation Forest.
    Identifies events that deviate from user/host baseline.
    """
    
    def __init__(self, contamination: float = 0.1):
        """
        Args:
            contamination: Expected proportion of anomalies (0-1)
        """
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def extract_features(self, event: Dict) -> List[float]:
        """
        Extract numerical features from an event for ML.
        Features:
        1. Hour of day (0-23)
        2. Day of week (0-6)
        3. Process creation rate in last hour (0-1000 normalized)
        4. Network connection count in last hour (0-100 normalized)
        5. File modification count in last hour (0-100 normalized)
        6. Login attempt count in last hour (0-10 normalized)
        7. Failed login count in last hour (0-10 normalized)
        8. Protocol rarity score (0-1)
        9. Port rarity score (0-1)
        10. Target system rarity score (0-1)
        """
        
        features = []
        
        # Temporal features
        timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        features.append(timestamp.hour)
        features.append(timestamp.weekday())
        
        # Event rate features (normalized 0-1)
        features.append(min(event.get('process_creation_rate_1h', 0) / 1000, 1.0))
        features.append(min(event.get('network_connection_count_1h', 0) / 100, 1.0))
        features.append(min(event.get('file_modification_count_1h', 0) / 100, 1.0))
        features.append(min(event.get('login_attempt_count_1h', 0) / 10, 1.0))
        features.append(min(event.get('failed_login_count_1h', 0) / 10, 1.0))
        
        # Rarity features (0-1, where 1 = very rare)
        features.append(event.get('protocol_rarity', 0.5))
        features.append(event.get('port_rarity', 0.5))
        features.append(event.get('target_rarity', 0.5))
        
        return features
    
    def fit_baseline(self, historical_events: List[Dict]) -> None:
        """
        Train anomaly detector on historical events.
        Call this periodically (e.g., weekly) with normal events.
        """
        if len(historical_events) < 100:
            raise ValueError("Need at least 100 historical events to fit baseline")
        
        # Extract features from all events
        feature_matrix = np.array([
            self.extract_features(event) for event in historical_events
        ])
        
        # Standardize features
        feature_matrix = self.scaler.fit_transform(feature_matrix)
        
        # Fit Isolation Forest
        self.model.fit(feature_matrix)
        self.is_fitted = True
    
    def score_event(self, event: Dict) -> float:
        """
        Score an event for anomaly (0-1, where 1 = most anomalous).
        Returns -1 if model not fitted.
        """
        if not self.is_fitted:
            return -1.0
        
        # Extract features
        features = self.extract_features(event)
        features_scaled = self.scaler.transform([features])
        
        # Get anomaly score (-1 to 1, where -1 = normal, 1 = anomalous)
        anomaly_score = self.model.score_samples(features_scaled)[0]
        
        # Convert to 0-1 scale (0 = normal, 1 = anomalous)
        # Isolation Forest score ranges from -1 to ~0.5
        # Map to 0-1 where negative scores -> 0 and positive -> 1
        normalized_score = max(0.0, min(1.0, (anomaly_score + 1.0) / 2.0))
        
        return normalized_score
    
    def detect_anomalies(self, events: List[Dict], 
                        threshold: float = 0.5) -> List[Tuple[Dict, float]]:
        """
        Detect anomalous events in a batch.
        Returns: List of (event, anomaly_score) tuples
        """
        anomalies = []
        
        for event in events:
            score = self.score_event(event)
            if score >= threshold:
                anomalies.append((event, score))
        
        # Sort by anomaly score (highest first)
        anomalies.sort(key=lambda x: x[1], reverse=True)
        
        return anomalies


class UserBaselineBuilder:
    """Builds behavioral baselines from historical data"""
    
    def build_user_baseline(self, historical_events: List[Dict], 
                           uid: str) -> UserBaseline:
        """
        Build baseline from historical events for a user.
        """
        if not historical_events:
            raise ValueError("No historical events provided")
        
        # Calculate events per hour
        events_per_hour = self._calculate_events_per_hour(historical_events)
        avg_events = np.mean(events_per_hour)
        std_events = np.std(events_per_hour)
        
        # Time distribution: probability of activity at each hour
        time_distribution = self._calculate_time_distribution(historical_events)
        
        # Typical actions
        typical_actions = self._calculate_action_frequency(historical_events)
        
        # Typical targets
        typical_targets = self._calculate_target_frequency(historical_events)
        
        # Typical login locations (IP geolocations)
        typical_locations = self._extract_typical_locations(historical_events)
        
        # Typical login hours
        login_hours = self._calculate_login_hours(historical_events)
        
        # MFA success rate
        mfa_success = self._calculate_mfa_success_rate(historical_events)
        
        return UserBaseline(
            uid=uid,
            avg_events_per_hour=avg_events,
            events_per_hour_std=std_events,
            time_distribution=time_distribution,
            typical_actions=typical_actions,
            typical_targets=typical_targets,
            typical_locations=typical_locations,
            typical_login_hours=login_hours,
            mfa_success_rate=mfa_success,
            last_updated=datetime.now().isoformat() + 'Z'
        )
    
    @staticmethod
    def _calculate_events_per_hour(events: List[Dict]) -> List[float]:
        """Calculate event count per hour"""
        hourly_counts = {}
        
        for event in events:
            timestamp = datetime.fromisoformat(
                event['timestamp'].replace('Z', '+00:00')
            )
            hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
            
            hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
        
        return list(hourly_counts.values())
    
    @staticmethod
    def _calculate_time_distribution(events: List[Dict]) -> Dict[int, float]:
        """Calculate probability of activity at each hour (0-23)"""
        hour_counts = {i: 0 for i in range(24)}
        
        for event in events:
            timestamp = datetime.fromisoformat(
                event['timestamp'].replace('Z', '+00:00')
            )
            hour_counts[timestamp.hour] += 1
        
        # Convert to probabilities
        total = sum(hour_counts.values())
        return {
            hour: count / total if total > 0 else 0
            for hour, count in hour_counts.items()
        }
    
    @staticmethod
    def _calculate_action_frequency(events: List[Dict]) -> Dict[str, float]:
        """Calculate frequency of each action type"""
        action_counts = {}
        
        for event in events:
            action = event.get('action_type', 'unknown')
            action_counts[action] = action_counts.get(action, 0) + 1
        
        total = sum(action_counts.values())
        return {
            action: count / total if total > 0 else 0
            for action, count in action_counts.items()
        }
    
    @staticmethod
    def _calculate_target_frequency(events: List[Dict]) -> Dict[str, float]:
        """Calculate frequency of targets accessed"""
        target_counts = {}
        
        for event in events:
            target = event.get('target', 'unknown')
            target_counts[target] = target_counts.get(target, 0) + 1
        
        total = sum(target_counts.values())
        return {
            target: count / total if total > 0 else 0
            for target, count in target_counts.items()
        }
    
    @staticmethod
    def _extract_typical_locations(events: List[Dict]) -> List[str]:
        """Extract typical login locations (IP geolocation)"""
        locations = {}
        
        for event in events:
            if event.get('event_type') == 'login':
                location = event.get('location', 'unknown')
                locations[location] = locations.get(location, 0) + 1
        
        # Return top 5 locations
        sorted_locs = sorted(locations.items(), key=lambda x: x[1], reverse=True)
        return [loc for loc, _ in sorted_locs[:5]]
    
    @staticmethod
    def _calculate_login_hours(events: List[Dict]) -> Tuple[int, int]:
        """Calculate typical login hours (start, end in UTC)"""
        login_hours = []
        
        for event in events:
            if event.get('event_type') == 'login' and event.get('status') == 'success':
                timestamp = datetime.fromisoformat(
                    event['timestamp'].replace('Z', '+00:00')
                )
                login_hours.append(timestamp.hour)
        
        if not login_hours:
            return (8, 18)  # Default 8am-6pm
        
        # Return 10th and 90th percentile
        sorted_hours = sorted(login_hours)
        return (
            sorted_hours[len(sorted_hours) // 10],
            sorted_hours[len(sorted_hours) * 9 // 10]
        )
    
    @staticmethod
    def _calculate_mfa_success_rate(events: List[Dict]) -> float:
        """Calculate MFA success rate"""
        mfa_attempts = 0
        mfa_successes = 0
        
        for event in events:
            if event.get('mfa_attempted'):
                mfa_attempts += 1
                if event.get('mfa_success'):
                    mfa_successes += 1
        
        if mfa_attempts == 0:
            return 1.0  # Unknown, assume high
        
        return mfa_successes / mfa_attempts
```

---

## Part 3: Graph-Based Attack Path Analysis

### 3.1 Attack Path Detection (Python + Neo4j)

```python
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta

@dataclass
class GraphNode:
    node_id: str
    entity_type: str  # 'user', 'host', 'process', 'ip', 'domain'
    entity_id: str
    timestamp: datetime
    risk_score: float

@dataclass
class GraphEdge:
    from_node_id: str
    to_node_id: str
    edge_type: str  # 'logged_into', 'executed', 'connected_to'
    timestamp: datetime
    confidence: float  # Likelihood of causal relationship
    
class AttackPathFinder:
    """
    Finds attack paths in the entity relationship graph.
    Uses BFS to identify suspicious sequences of entity interactions.
    """
    
    def __init__(self, max_path_length: int = 10, max_temporal_gap: int = 300):
        """
        Args:
            max_path_length: Maximum nodes in a path (to avoid explosive growth)
            max_temporal_gap: Maximum seconds between consecutive nodes in path
        """
        self.max_path_length = max_path_length
        self.max_temporal_gap = timedelta(seconds=max_temporal_gap)
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
    
    def add_node(self, node: GraphNode) -> None:
        """Add node to graph"""
        self.nodes[node.node_id] = node
    
    def add_edge(self, edge: GraphEdge) -> None:
        """Add edge to graph"""
        self.edges.append(edge)
    
    def find_attack_paths(self, 
                         start_entity: str,
                         end_entity: str,
                         suspicious_only: bool = True) -> List[List[GraphNode]]:
        """
        Find all attack paths from start to end entity.
        Uses BFS to explore relationship graph.
        """
        paths = []
        visited = set()
        
        def bfs(current_node_id: str, target_node_id: str, 
                path: List[GraphNode], depth: int):
            
            if depth > self.max_path_length:
                return
            
            if current_node_id == target_node_id and len(path) > 1:
                paths.append(list(path))
                return
            
            if current_node_id in visited:
                return
            
            visited.add(current_node_id)
            
            # Find all outgoing edges from current node
            for edge in self.edges:
                if edge.from_node_id == current_node_id:
                    next_node = self.nodes.get(edge.to_node_id)
                    if next_node and next_node.node_id not in visited:
                        # Check temporal ordering
                        last_timestamp = path[-1].timestamp if path else datetime.min
                        if next_node.timestamp > last_timestamp:
                            time_gap = next_node.timestamp - last_timestamp
                            if time_gap <= self.max_temporal_gap:
                                path.append(next_node)
                                bfs(edge.to_node_id, target_node_id, path, depth + 1)
                                path.pop()
            
            visited.remove(current_node_id)
        
        # Start BFS from start entity
        start_node = self.nodes.get(start_entity)
        if start_node:
            bfs(start_entity, end_entity, [start_node], 0)
        
        if suspicious_only:
            # Filter paths by suspicion score
            paths = [p for p in paths if self._calculate_path_risk(p) > 0.7]
        
        return paths
    
    def find_lateral_movement_chains(self, 
                                     events: List[Dict]) -> List[List[Dict]]:
        """
        Find lateral movement patterns:
        User logs into Host A -> Process on Host A connects to Host B -> 
        Attacker can access Host B
        """
        chains = []
        
        # Group events by user and host
        user_hosts = {}  # user_id -> [hosts]
        host_processes = {}  # host_id -> [processes]
        
        for event in events:
            if event.get('event_type') == 'login':
                user = event.get('user')
                host = event.get('host')
                if user and host:
                    user_hosts.setdefault(user, []).append(host)
            
            elif event.get('event_type') == 'process_execution':
                host = event.get('host')
                process = event.get('process')
                if host and process:
                    host_processes.setdefault(host, []).append(process)
        
        # Find chains: user -> host A -> process -> connection to host B
        for user, hosts in user_hosts.items():
            for source_host in hosts:
                # Find processes on this host
                processes = host_processes.get(source_host, [])
                for process in processes:
                    # Find network connections from this process
                    for event in events:
                        if (event.get('event_type') == 'network_connection' and
                            event.get('process') == process):
                            target_host = event.get('remote_host')
                            if target_host and target_host != source_host:
                                chain = [
                                    {'type': 'login', 'user': user, 'host': source_host},
                                    {'type': 'process_execution', 'process': process, 'host': source_host},
                                    {'type': 'network_connection', 'target_host': target_host}
                                ]
                                chains.append(chain)
        
        return chains
    
    def calculate_path_risk(self, path: List[GraphNode]) -> float:
        """
        Calculate risk score for a path.
        Combines individual node risks and edge confidence.
        """
        if not path:
            return 0.0
        
        # Average node risk scores
        node_risk = np.mean([node.risk_score for node in path]) if path else 0
        
        # Find edges connecting these nodes and average their confidence
        path_node_ids = [node.node_id for node in path]
        edge_risks = []
        
        for i in range(len(path_node_ids) - 1):
            from_id = path_node_ids[i]
            to_id = path_node_ids[i + 1]
            
            for edge in self.edges:
                if edge.from_node_id == from_id and edge.to_node_id == to_id:
                    edge_risks.append(edge.confidence)
        
        edge_risk = np.mean(edge_risks) if edge_risks else 0.5
        
        # Combined risk (weighted average)
        total_risk = 0.6 * node_risk + 0.4 * edge_risk
        
        return min(1.0, total_risk)
    
    @staticmethod
    def _calculate_path_risk(path: List[GraphNode]) -> float:
        """Calculate suspicion score for a path"""
        if not path:
            return 0.0
        
        # Sum of node risks + temporal coherence
        node_risk = sum(node.risk_score for node in path) / len(path)
        
        # Temporal coherence (consecutive events should be recent)
        temporal_coherence = 1.0
        for i in range(len(path) - 1):
            time_diff = (path[i + 1].timestamp - path[i].timestamp).total_seconds()
            if time_diff > 3600:  # More than 1 hour apart
                temporal_coherence *= 0.8
        
        return node_risk * temporal_coherence
```

---

## Part 4: Cost Optimization Strategies

### 4.1 Tiered RCA Approach

```python
class RCATiering:
    """
    Implements cost-optimized RCA strategy:
    - Tier 1 (90% of incidents): Rule-based, <$0.01
    - Tier 2 (8% of incidents): LLM confidence scoring, $0.05-0.10
    - Tier 3 (2% of incidents): Full LLM analysis, $0.50-2.00
    """
    
    def __init__(self):
        self.deterministic_rca_engine = DeterministicRCAEngine()
        self.llm_client = LLMClient()  # OpenAI / Anthropic API
    
    def classify_incident(self, package: InvestigationPackage) -> str:
        """
        Classify incident into tier based on characteristics.
        Returns: 'tier_1', 'tier_2', or 'tier_3'
        """
        
        # Check if attack matches known patterns (Tier 1)
        known_pattern_match = self._check_known_patterns(package)
        if known_pattern_match['confidence'] > 0.85:
            return 'tier_1'
        
        # Check if we have enough evidence for deterministic analysis
        evidence_quality = self._assess_evidence_quality(package)
        if evidence_quality['completeness'] > 0.90:
            return 'tier_1'
        
        # Check if incident is novel/unusual (Tier 3)
        novelty_score = self._calculate_novelty(package)
        if novelty_score > 0.7:
            return 'tier_3'
        
        # Default: Tier 2 (use LLM to assess confidence)
        return 'tier_2'
    
    def analyze_incident(self, package: InvestigationPackage) -> tuple:
        """
        Analyze incident with tier-appropriate method.
        Returns: (rca_result, cost_estimated, method)
        """
        
        tier = self.classify_incident(package)
        
        if tier == 'tier_1':
            # Rule-based RCA
            result = self.deterministic_rca_engine.analyze(package)
            return result, 0.01, 'deterministic'
        
        elif tier == 'tier_2':
            # Deterministic analysis + LLM confidence check
            det_result = self.deterministic_rca_engine.analyze(package)
            
            # Ask LLM if we have sufficient confidence
            confidence_prompt = f"""
            Based on this incident analysis:
            {det_result.narrative}
            
            Do we have sufficient confidence in this root cause assessment?
            Score 0-100 where 100 = very confident, 0 = no confidence.
            
            Also suggest what additional evidence would improve confidence.
            """
            
            confidence_check = self.llm_client.query(confidence_prompt, tokens=500)
            
            # If LLM says low confidence, escalate to Tier 3
            if confidence_check['confidence_score'] < 60:
                return self.analyze_with_llm(package), 1.50, 'llm'
            else:
                return det_result, 0.08, 'deterministic_with_llm_validation'
        
        else:  # tier_3
            # Full LLM analysis
            result = self.analyze_with_llm(package)
            return result, 1.50, 'llm'
    
    def analyze_with_llm(self, package: InvestigationPackage) -> Dict:
        """
        Full LLM analysis for complex incidents.
        ~$1-2 cost per incident.
        """
        
        # Prepare comprehensive prompt
        prompt = self._prepare_analysis_prompt(package)
        
        # Query LLM with streaming (to reduce token cost)
        result = self.llm_client.query(
            prompt,
            tokens=2000,
            temperature=0.2,  # Low temp for consistency
            stream=True  # Stream to avoid timeout
        )
        
        return result
    
    @staticmethod
    def _prepare_analysis_prompt(package: InvestigationPackage) -> str:
        """Prepare prompt for LLM analysis"""
        return f"""
You are a senior security incident response analyst. Analyze this incident:

Timeline:
{format_timeline(package.timeline)}

Attack Graph:
{format_attack_graph(package.attack_graph)}

Key Findings:
{format_findings(package.key_findings)}

Determine:
1. Root cause (initial compromise vector)
2. Attack progression (kill chain)
3. Impacted assets and data
4. Immediate containment actions
5. Long-term remediation
6. Confidence assessment (0-1)

Be concise and actionable.
"""
    
    def _check_known_patterns(self, package: InvestigationPackage) -> Dict:
        """Check if attack matches known patterns"""
        # Implement pattern matching against known attacks
        # (ransomware, phishing, credential compromise, etc.)
        pass
    
    def _assess_evidence_quality(self, package: InvestigationPackage) -> Dict:
        """Assess quality and completeness of evidence"""
        # Check confidence scores, gaps, etc.
        pass
    
    def _calculate_novelty(self, package: InvestigationPackage) -> float:
        """Calculate how novel/unusual this attack is"""
        # Compare against historical incidents
        pass
```

---

## Summary & Quick Start

```bash
# Quick start: Set up development environment

# 1. Clone repository
git clone <repo-url>
cd ai-native-soc-platform

# 2. Create Python virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# 3. Install dependencies
pip install -r requirements.txt
# Key packages:
# - kafka-python: Event streaming
# - neo4j: Graph database
# - scikit-learn: ML/anomaly detection
# - openai: LLM integration
# - pydantic: Data validation
# - pytest: Testing

# 4. Start Docker services (Kafka, Neo4j, PostgreSQL, Redis)
docker-compose up -d

# 5. Run tests
pytest tests/ -v

# 6. Start alert intake service
python services/alert_intake/main.py

# 7. Start evidence collection service
python services/evidence_collection/main.py

# 8. Start correlation/compression service
python services/correlation/main.py
```

---

**Document Version**: 1.0  
**Status**: Ready for Implementation
