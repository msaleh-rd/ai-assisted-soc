"""Investigation Package Builder - Phase 2

Creates curated investigation packages from compressed events.
Includes evidence selection, ranking, and confidence scoring.
"""

from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
import json
import hashlib
from collections import defaultdict

from backend.services.correlation_engine import CompressedPackage, CorrelatedEvent


class PackageType(Enum):
    """Types of investigation packages."""
    RAPID_CONTAINMENT = "rapid_containment"  # Quick high-confidence analysis
    DETAILED_RCA = "detailed_rca"  # Comprehensive investigation
    FORENSIC_ANALYSIS = "forensic_analysis"  # Deep technical analysis
    EXECUTIVE_SUMMARY = "executive_summary"  # High-level overview


@dataclass
class EntityNode:
    """Entity in the investigation graph."""
    entity_id: str
    entity_type: str  # user, host, process, ip, domain, file
    risk_score: float
    involvement_timeline: List[Dict] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)


@dataclass
class RelationshipEdge:
    """Relationship between entities."""
    from_entity: str
    to_entity: str
    relationship_type: str  # logged_into, executed, accessed, connected_to
    timestamp: datetime
    confidence: float
    evidence_events: List[Dict] = field(default_factory=list)


@dataclass
class InvestigationPackage:
    """Complete investigation package ready for RCA."""
    package_id: str
    package_type: PackageType
    investigation_id: str
    original_alert_id: str
    created_at: datetime
    updated_at: datetime
    
    # Core components
    timeline: List[Dict]
    entity_graph: Dict[str, EntityNode]
    relationships: List[RelationshipEdge]
    evidence_summary: Dict[str, Any]
    
    # Analysis metadata
    compression_ratio: float
    original_event_count: int
    compressed_event_count: int
    selected_event_count: int
    
    # Confidence metrics
    evidence_quality_score: float
    timeline_coherence: float
    attack_pattern_confidence: float
    overall_confidence: float
    
    # Detected patterns
    suspected_attack_types: List[str]
    detected_patterns: List[Dict]
    attack_phases: List[Dict]
    impacted_assets: List[str]
    
    # Recommended actions
    immediate_actions: List[Dict]
    investigation_queries: List[Dict]
    evidence_gaps: List[str]
    
    # Raw data for detailed analysis
    raw_events: List[Dict] = field(default_factory=list)


class EntityGraphBuilder:
    """Builds entity relationship graphs from correlated events."""
    
    def __init__(self):
        self.entities: Dict[str, EntityNode] = {}
        self.relationships: List[RelationshipEdge] = []
    
    def build_graph(self, events: List[CorrelatedEvent]) -> Tuple[Dict[str, EntityNode], 
                                                                   List[RelationshipEdge]]:
        """Build entity graph from events."""
        
        # Extract entities from events
        self._extract_entities(events)
        
        # Build relationships
        self._extract_relationships(events)
        
        return self.entities, self.relationships
    
    def _extract_entities(self, events: List[CorrelatedEvent]) -> None:
        """Extract unique entities from events."""
        
        entity_events = defaultdict(list)
        
        for event in events:
            entity_id = event.entity_id
            
            if entity_id not in self.entities:
                self.entities[entity_id] = EntityNode(
                    entity_id=entity_id,
                    entity_type=self._infer_entity_type(event),
                    risk_score=event.risk_score
                )
            
            self.entities[entity_id].involvement_timeline.append({
                'timestamp': event.timestamp.isoformat(),
                'action': event.action,
                'event_type': event.event_type
            })
            
            entity_events[entity_id].append(event)
        
        # Add evidence to entities
        for entity_id, events_list in entity_events.items():
            if entity_id in self.entities:
                for event in events_list:
                    self.entities[entity_id].evidence.extend(event.raw_events)
    
    def _extract_relationships(self, events: List[CorrelatedEvent]) -> None:
        """Extract entity relationships from events."""
        
        seen_edges = set()
        
        for event in events:
            # Parse entity_id (format: "user@host")
            parts = event.entity_id.split('@')
            
            if len(parts) == 2:
                from_entity, to_entity = parts
                
                edge_key = (from_entity, to_entity, event.action)
                
                if edge_key not in seen_edges:
                    relationship = RelationshipEdge(
                        from_entity=from_entity,
                        to_entity=to_entity,
                        relationship_type=self._infer_relationship_type(event.action),
                        timestamp=event.timestamp,
                        confidence=event.confidence,
                        evidence_events=event.raw_events
                    )
                    
                    self.relationships.append(relationship)
                    seen_edges.add(edge_key)
                    
                    # Add relationship reference to entities
                    if from_entity in self.entities:
                        self.entities[from_entity].relationships.append(to_entity)
    
    @staticmethod
    def _infer_entity_type(event: CorrelatedEvent) -> str:
        """Infer entity type from event."""
        
        if '@' in event.entity_id:
            return 'user_on_host'
        elif '.' in event.entity_id:  # Likely an IP
            return 'ip_address'
        elif event.event_type == 'process':
            return 'process'
        
        return 'unknown'
    
    @staticmethod
    def _infer_relationship_type(action: str) -> str:
        """Infer relationship type from action."""
        
        if action in ['login', 'failed_login', 'successful_login']:
            return 'logged_into'
        elif action in ['execute', 'process_execution']:
            return 'executed'
        elif action in ['access', 'file_access', 'data_read']:
            return 'accessed'
        elif action in ['connect', 'network_connection']:
            return 'connected_to'
        
        return 'related_to'


class EvidenceSelector:
    """Selects and ranks evidence for investigation packages."""
    
    def __init__(self, max_evidence_events: int = 500):
        self.max_evidence_events = max_evidence_events
    
    def select_evidence(self, 
                       compressed_package: CompressedPackage,
                       package_type: PackageType) -> Tuple[List[Dict], float]:
        """Select and rank evidence based on package type."""
        
        if package_type == PackageType.RAPID_CONTAINMENT:
            return self._select_rapid_evidence(compressed_package)
        elif package_type == PackageType.DETAILED_RCA:
            return self._select_detailed_evidence(compressed_package)
        elif package_type == PackageType.FORENSIC_ANALYSIS:
            return self._select_forensic_evidence(compressed_package)
        else:
            return self._select_executive_evidence(compressed_package)
    
    def _select_rapid_evidence(self, 
                               package: CompressedPackage) -> Tuple[List[Dict], float]:
        """Select high-confidence evidence for rapid containment."""
        
        # Filter events with high confidence and risk
        selected = [
            e for e in package.events 
            if e.risk_score > 0.7 and e.confidence > 0.6
        ]
        
        # Rank by risk score
        selected.sort(key=lambda e: e.risk_score, reverse=True)
        
        # Keep top events only
        selected = selected[:min(len(selected), 50)]
        
        quality_score = len(selected) / len(package.events) if package.events else 0
        
        return self._format_evidence(selected), quality_score
    
    def _select_detailed_evidence(self, 
                                 package: CompressedPackage) -> Tuple[List[Dict], float]:
        """Select comprehensive evidence for RCA."""
        
        # Include events across all risk levels
        selected = package.events
        
        # Rank by risk, then by confidence
        selected.sort(
            key=lambda e: (e.risk_score, e.confidence), 
            reverse=True
        )
        
        # Keep top events up to limit
        selected = selected[:min(len(selected), self.max_evidence_events)]
        
        quality_score = len(selected) / len(package.events) if package.events else 0
        
        return self._format_evidence(selected), quality_score
    
    def _select_forensic_evidence(self, 
                                 package: CompressedPackage) -> Tuple[List[Dict], float]:
        """Select complete evidence for forensic analysis."""
        
        # Include ALL events with full raw event data
        selected = package.events
        
        quality_score = 1.0 if selected else 0.0
        
        return self._format_evidence(selected), quality_score
    
    def _select_executive_evidence(self, 
                                  package: CompressedPackage) -> Tuple[List[Dict], float]:
        """Select high-level evidence for executive summary."""
        
        # Only highest confidence events
        selected = [
            e for e in package.events 
            if e.confidence > 0.8
        ]
        
        # Keep top events only
        selected = selected[:min(len(selected), 20)]
        
        quality_score = len(selected) / len(package.events) if package.events else 0.5
        
        return self._format_evidence(selected), quality_score
    
    @staticmethod
    def _format_evidence(events: List[CorrelatedEvent]) -> List[Dict]:
        """Format events for evidence."""
        
        formatted = []
        
        for event in events:
            formatted.append({
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'entity': event.entity_id,
                'action': event.action,
                'risk_score': event.risk_score,
                'confidence': event.confidence,
                'compression_ratio': event.compression_ratio,
                'raw_events_count': len(event.raw_events)
            })
        
        return formatted


class AttackPhaseAnalyzer:
    """Identifies and maps attack phases from events."""
    
    # MITRE ATT&CK phases
    KILL_CHAIN_PHASES = [
        'reconnaissance',
        'weaponization',
        'delivery',
        'exploitation',
        'installation',
        'command_and_control',
        'action_on_objectives'
    ]
    
    def analyze_phases(self, 
                      events: List[CorrelatedEvent],
                      patterns: List[Dict]) -> List[Dict]:
        """Identify attack phases from events."""
        
        phases = []
        
        for phase in self.KILL_CHAIN_PHASES:
            phase_events = [
                e for e in events 
                if self._matches_phase(e, phase)
            ]
            
            if phase_events:
                phases.append({
                    'phase': phase,
                    'event_count': len(phase_events),
                    'detected_at': min(e.timestamp for e in phase_events).isoformat(),
                    'confidence': self._calculate_phase_confidence(phase, phase_events, patterns)
                })
        
        return phases
    
    @staticmethod
    def _matches_phase(event: CorrelatedEvent, phase: str) -> bool:
        """Check if event matches attack phase."""
        
        phase_keywords = {
            'reconnaissance': ['scan', 'probe', 'enumerate', 'port_scan'],
            'weaponization': ['download', 'compile', 'create', 'package'],
            'delivery': ['email', 'usb', 'download', 'visit'],
            'exploitation': ['execute', 'exploit', 'privilege_escalation', 'vulnerability'],
            'installation': ['install', 'persistence', 'backdoor', 'malware'],
            'command_and_control': ['connect', 'beacon', 'c2', 'command'],
            'action_on_objectives': ['exfiltrate', 'delete', 'encrypt', 'modify']
        }
        
        if phase not in phase_keywords:
            return False
        
        keywords = phase_keywords[phase]
        event_text = f"{event.action} {event.event_type}".lower()
        
        return any(kw in event_text for kw in keywords)
    
    @staticmethod
    def _calculate_phase_confidence(phase: str, events: List[CorrelatedEvent], 
                                   patterns: List[Dict]) -> float:
        """Calculate confidence in detected phase."""
        
        # Base confidence from event count
        event_confidence = min(len(events) / 10, 1.0)
        
        # Boost from pattern matches
        pattern_boost = 0.0
        for pattern in patterns:
            if phase in str(pattern).lower():
                pattern_boost += 0.2
        
        return min(1.0, event_confidence + pattern_boost)


class InvestigationPackageBuilder:
    """Main builder for investigation packages."""
    
    def __init__(self):
        self.entity_graph_builder = EntityGraphBuilder()
        self.evidence_selector = EvidenceSelector()
        self.phase_analyzer = AttackPhaseAnalyzer()
    
    async def build_package(self,
                           compressed_package: CompressedPackage,
                           original_alert: Dict,
                           package_type: PackageType = PackageType.DETAILED_RCA) -> InvestigationPackage:
        """Build complete investigation package."""
        
        package_id = hashlib.md5(
            f"{compressed_package.investigation_id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()
        
        # Build entity graph
        entity_graph, relationships = self.entity_graph_builder.build_graph(
            compressed_package.events
        )
        
        # Select evidence
        selected_evidence, quality_score = self.evidence_selector.select_evidence(
            compressed_package,
            package_type
        )
        
        # Analyze attack phases
        attack_phases = self.phase_analyzer.analyze_phases(
            compressed_package.events,
            compressed_package.detected_patterns
        )
        
        # Build investigation package
        package = InvestigationPackage(
            package_id=package_id,
            package_type=package_type,
            investigation_id=compressed_package.investigation_id,
            original_alert_id=original_alert.get('alert_id', 'unknown'),
            created_at=datetime.now(),
            updated_at=datetime.now(),
            
            # Core components
            timeline=compressed_package.timeline,
            entity_graph={k: v for k, v in entity_graph.items()},
            relationships=relationships,
            evidence_summary={
                'selected_events': len(selected_evidence),
                'total_raw_events': compressed_package.original_event_count,
                'compression_stages': 7
            },
            
            # Analysis metadata
            compression_ratio=compressed_package.compression_ratio,
            original_event_count=compressed_package.original_event_count,
            compressed_event_count=compressed_package.compressed_event_count,
            selected_event_count=len(selected_evidence),
            
            # Confidence metrics
            evidence_quality_score=quality_score,
            timeline_coherence=self._calculate_timeline_coherence(compressed_package.timeline),
            attack_pattern_confidence=self._calculate_pattern_confidence(
                compressed_package.detected_patterns
            ),
            overall_confidence=compressed_package.confidence,
            
            # Detected patterns
            suspected_attack_types=self._extract_attack_types(compressed_package.detected_patterns),
            detected_patterns=compressed_package.detected_patterns,
            attack_phases=attack_phases,
            impacted_assets=list(entity_graph.keys()),
            
            # Recommended actions
            immediate_actions=self._generate_immediate_actions(compressed_package),
            investigation_queries=self._generate_investigation_queries(entity_graph),
            evidence_gaps=self._identify_evidence_gaps(compressed_package),
            
            # Raw data
            raw_events=[
                {
                    'event_id': e.event_id,
                    'timestamp': e.timestamp.isoformat(),
                    'event_type': e.event_type,
                    'entity': e.entity_id,
                    'action': e.action
                }
                for e in compressed_package.events
            ]
        )
        
        return package
    
    @staticmethod
    def _calculate_timeline_coherence(timeline: List[Dict]) -> float:
        """Calculate timeline coherence."""
        
        if len(timeline) < 2:
            return 0.5
        
        # Check for gaps in timeline
        timestamps = []
        for event in timeline:
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                timestamps.append(ts)
            except:
                pass
        
        if len(timestamps) < 2:
            return 0.5
        
        # Calculate average gap between events
        gaps = []
        for i in range(len(timestamps) - 1):
            gap = (timestamps[i + 1] - timestamps[i]).total_seconds()
            gaps.append(gap)
        
        avg_gap = sum(gaps) / len(gaps) if gaps else 0
        
        # Coherence is high if events are closely spaced (attack)
        if avg_gap < 300:  # < 5 minutes
            return 0.9
        elif avg_gap < 3600:  # < 1 hour
            return 0.7
        else:
            return 0.4
    
    @staticmethod
    def _calculate_pattern_confidence(patterns: List[Dict]) -> float:
        """Calculate confidence based on detected patterns."""
        
        if not patterns:
            return 0.3
        
        avg_confidence = sum(p.get('confidence', 0.5) for p in patterns) / len(patterns)
        
        return min(1.0, avg_confidence)
    
    @staticmethod
    def _extract_attack_types(patterns: List[Dict]) -> List[str]:
        """Extract unique attack types from patterns."""
        
        types = set()
        
        for pattern in patterns:
            attack_type = pattern.get('type', 'unknown')
            types.add(attack_type)
        
        return list(types)
    
    @staticmethod
    def _generate_immediate_actions(package: CompressedPackage) -> List[Dict]:
        """Generate immediate containment actions."""
        
        actions = []
        
        # Isolate affected hosts
        actions.append({
            'action': 'isolate_hosts',
            'priority': 'critical',
            'description': 'Isolate affected hosts from network',
            'estimated_time': '5 minutes'
        })
        
        # Reset compromised credentials
        actions.append({
            'action': 'reset_credentials',
            'priority': 'critical',
            'description': 'Reset credentials for affected user accounts',
            'estimated_time': '10 minutes'
        })
        
        # Block C2 communications
        if any(p['type'] == 'command_and_control' for p in package.detected_patterns if isinstance(p, dict)):
            actions.append({
                'action': 'block_c2',
                'priority': 'critical',
                'description': 'Block command and control communications',
                'estimated_time': '5 minutes'
            })
        
        return actions
    
    @staticmethod
    def _generate_investigation_queries(entity_graph: Dict[str, EntityNode]) -> List[Dict]:
        """Generate investigation queries for analysts."""
        
        queries = []
        
        for entity_id in entity_graph:
            queries.append({
                'entity': entity_id,
                'query_type': 'timeline',
                'description': f'Get full timeline for {entity_id}',
                'priority': 'high'
            })
        
        return queries
    
    @staticmethod
    def _identify_evidence_gaps(package: CompressedPackage) -> List[str]:
        """Identify gaps in evidence."""
        
        gaps = []
        
        # Check for missing network logs
        if not any('network' in str(e) for e in package.events):
            gaps.append('No network communication events found')
        
        # Check for missing process execution logs
        if not any('process' in str(e) for e in package.events):
            gaps.append('No process execution events found')
        
        # Check for missing file access logs
        if not any('file' in str(e) for e in package.events):
            gaps.append('No file access events found')
        
        return gaps
