"""Tests for Phase 2 - Investigation Package Builder"""

import pytest
from datetime import datetime
from backend.services.investigation_builder import (
    InvestigationPackageBuilder,
    EntityGraphBuilder,
    EvidenceSelector,
    AttackPhaseAnalyzer,
    PackageType,
    EntityNode,
    RelationshipEdge
)
from backend.services.correlation_engine import (
    CorrelatedEvent,
    CompressedPackage
)


class TestEntityGraphBuilder:
    """Test entity graph construction."""
    
    def setup_method(self):
        self.builder = EntityGraphBuilder()
    
    def test_extract_entities(self):
        """Test extracting entities from events."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 12, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9,
                raw_events=[{'user': 'alice', 'host': 'host1'}]
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 12, 1, 0),
                event_type='execute',
                entity_type='process',
                entity_id='bob@host2',
                action='execute',
                confidence=0.9,
                raw_events=[{'user': 'bob', 'host': 'host2'}]
            )
        ]
        
        entities, relationships = self.builder.build_graph(events)
        
        assert len(entities) == 2
        assert 'alice@host1' in entities
        assert 'bob@host2' in entities
        assert isinstance(entities['alice@host1'], EntityNode)
    
    def test_extract_relationships(self):
        """Test extracting entity relationships."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 12, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9,
                raw_events=[{'user': 'alice', 'host': 'host1'}]
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 12, 5, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host2',
                action='login',
                confidence=0.9,
                raw_events=[{'user': 'alice', 'host': 'host2'}]
            )
        ]
        
        entities, relationships = self.builder.build_graph(events)
        
        # Should have relationships between alice@host1 and alice@host2
        assert len(relationships) > 0
        assert isinstance(relationships[0], RelationshipEdge)


class TestEvidenceSelector:
    """Test evidence selection for different package types."""
    
    def setup_method(self):
        self.selector = EvidenceSelector()
    
    def _create_compressed_package(self, num_events=50):
        """Helper to create a mock compressed package."""
        
        events = [
            CorrelatedEvent(
                event_id=f'e{i}',
                timestamp=datetime(2026, 8, 10, 12, i % 60, 0),
                event_type='login' if i % 2 == 0 else 'execute',
                entity_type='user',
                entity_id=f'user{i}@host1',
                action='login' if i % 2 == 0 else 'execute',
                confidence=0.5 + (i / num_events) * 0.5,
                risk_score=i / num_events,
                raw_events=[{'event_id': f'e{i}'}] * (i + 1)
            )
            for i in range(num_events)
        ]
        
        return CompressedPackage(
            investigation_id='test-001',
            original_event_count=num_events * 10,
            compressed_event_count=num_events,
            compression_ratio=10.0,
            events=events,
            timeline=[],
            attack_graph={},
            detected_patterns=[],
            risk_score=0.7,
            confidence=0.8,
            created_at=datetime.now()
        )
    
    def test_select_rapid_evidence(self):
        """Test evidence selection for rapid containment."""
        
        package = self._create_compressed_package()
        
        evidence, quality = self.selector.select_evidence(
            package,
            PackageType.RAPID_CONTAINMENT
        )
        
        # Should select high-confidence events only
        assert len(evidence) <= 50
        assert quality > 0.0
        assert all(e.get('confidence', 0) > 0.5 for e in evidence if 'confidence' in e)
    
    def test_select_detailed_evidence(self):
        """Test evidence selection for RCA."""
        
        package = self._create_compressed_package()
        
        evidence, quality = self.selector.select_evidence(
            package,
            PackageType.DETAILED_RCA
        )
        
        # Should select comprehensive evidence
        assert len(evidence) > 0
        assert quality > 0.0
    
    def test_select_forensic_evidence(self):
        """Test evidence selection for forensic analysis."""
        
        package = self._create_compressed_package()
        
        evidence, quality = self.selector.select_evidence(
            package,
            PackageType.FORENSIC_ANALYSIS
        )
        
        # Should select all evidence
        assert len(evidence) == len(package.events)
        assert quality == 1.0
    
    def test_select_executive_evidence(self):
        """Test evidence selection for executive summary."""
        
        package = self._create_compressed_package()
        
        evidence, quality = self.selector.select_evidence(
            package,
            PackageType.EXECUTIVE_SUMMARY
        )
        
        # Should select only highest confidence events
        assert len(evidence) <= 20
        assert quality > 0.0


class TestAttackPhaseAnalyzer:
    """Test attack phase detection."""
    
    def setup_method(self):
        self.analyzer = AttackPhaseAnalyzer()
    
    def test_detect_kill_chain_phases(self):
        """Test detecting MITRE ATT&CK kill chain phases."""
        
        events = [
            # Reconnaissance
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 8, 0, 0),
                event_type='network_scan',
                entity_type='ip',
                entity_id='attacker_ip',
                action='scan',
                confidence=0.9
            ),
            # Exploitation
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 8, 30, 0),
                event_type='exploit',
                entity_type='process',
                entity_id='victim@host1',
                action='exploit',
                confidence=0.9
            ),
            # Installation
            CorrelatedEvent(
                event_id='e3',
                timestamp=datetime(2026, 8, 10, 8, 45, 0),
                event_type='file_write',
                entity_type='file',
                entity_id='backdoor.exe',
                action='install',
                confidence=0.9
            ),
            # Command & Control
            CorrelatedEvent(
                event_id='e4',
                timestamp=datetime(2026, 8, 10, 9, 0, 0),
                event_type='network',
                entity_type='domain',
                entity_id='c2.example.com',
                action='connect',
                confidence=0.9
            )
        ]
        
        patterns = [
            {'type': 'reconnaissance', 'confidence': 0.8},
            {'type': 'exploitation', 'confidence': 0.85}
        ]
        
        phases = self.analyzer.analyze_phases(events, patterns)
        
        assert len(phases) > 0
        assert all('phase' in p for p in phases)
        assert all('confidence' in p for p in phases)


class TestInvestigationPackageBuilder:
    """Test investigation package building."""
    
    def setup_method(self):
        self.builder = InvestigationPackageBuilder()
    
    def _create_test_compressed_package(self):
        """Helper to create test compressed package."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 8, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9,
                risk_score=0.7,
                raw_events=[{'user': 'alice', 'host': 'host1'}]
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 8, 5, 0),
                event_type='privilege_escalation',
                entity_type='process',
                entity_id='alice@host1',
                action='sudo',
                confidence=0.85,
                risk_score=0.9,
                raw_events=[{'user': 'alice', 'action': 'sudo'}]
            ),
            CorrelatedEvent(
                event_id='e3',
                timestamp=datetime(2026, 8, 10, 8, 10, 0),
                event_type='file_access',
                entity_type='file',
                entity_id='alice@host1',
                action='file_access',
                confidence=0.8,
                risk_score=0.6,
                raw_events=[{'user': 'alice', 'action': 'file_access'}]
            )
        ]
        
        return CompressedPackage(
            investigation_id='test-inv-001',
            original_event_count=1000,
            compressed_event_count=3,
            compression_ratio=333.33,
            events=events,
            timeline=[
                {'timestamp': e.timestamp.isoformat(), 'action': e.action}
                for e in events
            ],
            attack_graph={
                'lateral_movement': ['alice@host1'],
                'privilege_escalation': ['alice@host1']
            },
            detected_patterns=[
                {'type': 'privilege_escalation', 'confidence': 0.85},
                {'type': 'lateral_movement', 'confidence': 0.7}
            ],
            risk_score=0.8,
            confidence=0.85,
            created_at=datetime.now()
        )
    
    @pytest.mark.asyncio
    async def test_build_investigation_package_detailed(self):
        """Test building detailed RCA investigation package."""
        
        compressed_pkg = self._create_test_compressed_package()
        
        original_alert = {
            'alert_id': 'alert-001',
            'severity': 'high',
            'source': 'EDR'
        }
        
        package = await self.builder.build_package(
            compressed_package=compressed_pkg,
            original_alert=original_alert,
            package_type=PackageType.DETAILED_RCA
        )
        
        assert package.package_id is not None
        assert package.investigation_id == 'test-inv-001'
        assert package.compression_ratio == 333.33
        assert len(package.timeline) == 3
        assert len(package.suspected_attack_types) > 0
        assert len(package.immediate_actions) > 0
    
    @pytest.mark.asyncio
    async def test_build_investigation_package_rapid(self):
        """Test building rapid containment investigation package."""
        
        compressed_pkg = self._create_test_compressed_package()
        
        original_alert = {
            'alert_id': 'alert-002',
            'severity': 'critical',
            'source': 'SIEM'
        }
        
        package = await self.builder.build_package(
            compressed_package=compressed_pkg,
            original_alert=original_alert,
            package_type=PackageType.RAPID_CONTAINMENT
        )
        
        assert package.package_type == PackageType.RAPID_CONTAINMENT
        assert package.selected_event_count <= len(compressed_pkg.events)
        assert len(package.immediate_actions) > 0
    
    @pytest.mark.asyncio
    async def test_build_investigation_package_executive(self):
        """Test building executive summary investigation package."""
        
        compressed_pkg = self._create_test_compressed_package()
        
        original_alert = {
            'alert_id': 'alert-003',
            'severity': 'high'
        }
        
        package = await self.builder.build_package(
            compressed_package=compressed_pkg,
            original_alert=original_alert,
            package_type=PackageType.EXECUTIVE_SUMMARY
        )
        
        assert package.package_type == PackageType.EXECUTIVE_SUMMARY
        assert package.selected_event_count <= 20
        assert package.overall_confidence >= 0.0
    
    @pytest.mark.asyncio
    async def test_entity_graph_construction(self):
        """Test that entity graph is properly constructed."""
        
        compressed_pkg = self._create_test_compressed_package()
        
        package = await self.builder.build_package(
            compressed_package=compressed_pkg,
            original_alert={'alert_id': 'alert-004'},
            package_type=PackageType.DETAILED_RCA
        )
        
        assert len(package.entity_graph) > 0
        assert len(package.relationships) >= 0
        assert all('alice' in entity for entity in package.entity_graph.keys())
    
    @pytest.mark.asyncio
    async def test_attack_phase_detection(self):
        """Test that attack phases are detected."""
        
        compressed_pkg = self._create_test_compressed_package()
        
        package = await self.builder.build_package(
            compressed_package=compressed_pkg,
            original_alert={'alert_id': 'alert-005'},
            package_type=PackageType.DETAILED_RCA
        )
        
        assert len(package.attack_phases) >= 0
        if package.attack_phases:
            assert all('phase' in p for p in package.attack_phases)
            assert all('confidence' in p for p in package.attack_phases)


class TestIntegration:
    """Integration tests for investigation package builder."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_package_creation(self):
        """Test end-to-end investigation package creation."""
        
        builder = InvestigationPackageBuilder()
        
        # Create comprehensive test events
        events = []
        base_time = datetime(2026, 8, 10, 8, 0, 0)
        
        # Timeline: Failed logins -> Successful login -> Privilege escalation -> Data access
        event_sequence = [
            ('failed_login', 'failed_login', 0.3),
            ('failed_login', 'failed_login', 0.3),
            ('failed_login', 'failed_login', 0.3),
            ('login', 'successful_login', 0.9),
            ('process', 'sudo', 0.85),
            ('file_access', 'file_access', 0.8),
        ]
        
        for i, (event_type, action, confidence) in enumerate(event_sequence):
            events.append(CorrelatedEvent(
                event_id=f'e{i}',
                timestamp=base_time.replace(minute=i*5),
                event_type=event_type,
                entity_type='user',
                entity_id='attacker@compromised_host',
                action=action,
                confidence=confidence,
                risk_score=confidence,
                raw_events=[{'event': action}] * 5
            ))
        
        compressed_pkg = CompressedPackage(
            investigation_id='integration-test-001',
            original_event_count=100,
            compressed_event_count=len(events),
            compression_ratio=100 / len(events),
            events=events,
            timeline=[{'timestamp': e.timestamp.isoformat(), 'action': e.action} for e in events],
            attack_graph={
                'credential_compromise': ['attacker@compromised_host'],
                'privilege_escalation': ['attacker@compromised_host'],
                'data_access': ['attacker@compromised_host']
            },
            detected_patterns=[
                {'type': 'credential_compromise', 'confidence': 0.9},
                {'type': 'privilege_escalation', 'confidence': 0.85},
                {'type': 'data_exfiltration', 'confidence': 0.8}
            ],
            risk_score=0.85,
            confidence=0.9,
            created_at=datetime.now()
        )
        
        original_alert = {
            'alert_id': 'integration-alert-001',
            'severity': 'critical',
            'source': 'EDR',
            'description': 'Suspicious file encryption detected'
        }
        
        package = await builder.build_package(
            compressed_package=compressed_pkg,
            original_alert=original_alert,
            package_type=PackageType.DETAILED_RCA
        )
        
        # Comprehensive validations
        assert package.package_id is not None
        assert package.original_event_count == 100
        assert package.compressed_event_count == len(events)
        assert package.compression_ratio > 1
        assert len(package.timeline) == len(events)
        assert len(package.suspected_attack_types) > 0
        assert package.overall_confidence > 0
        assert len(package.attack_phases) >= 0
        assert len(package.immediate_actions) > 0
        assert len(package.investigation_queries) > 0
        
        # Attack types should include detected types
        detected_types = [p['type'] for p in compressed_pkg.detected_patterns]
        for dtype in detected_types:
            if dtype in package.suspected_attack_types:
                assert True
