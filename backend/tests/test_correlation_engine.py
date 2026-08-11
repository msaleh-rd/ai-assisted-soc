"""Tests for Phase 2 - Correlation & Compression Engine"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock
from backend.services.correlation_engine import (
    CorrelationEngine,
    TemporalFilter,
    EntityCorrelator,
    BehavioralFilter,
    EventDeduplicator,
    GraphAnalyzer,
    RiskScorer,
    CorrelatedEvent
)


class TestTemporalFilter:
    """Test temporal filtering stage."""
    
    def setup_method(self):
        self.filter = TemporalFilter(window_hours=24)
        self.incident_time = datetime(2026, 8, 10, 12, 0, 0)
    
    def test_filter_events_within_window(self):
        """Test filtering events within temporal window."""
        
        events = [
            {
                'timestamp': '2026-08-10T11:00:00Z',
                'event_type': 'login',
                'action': 'login'
            },
            {
                'timestamp': '2026-08-10T13:00:00Z',
                'event_type': 'process',
                'action': 'execute'
            },
            {
                'timestamp': '2026-08-05T12:00:00Z',
                'event_type': 'login',
                'action': 'login'  # Too far from incident
            }
        ]
        
        filtered, reduction = self.filter.filter_events(events, self.incident_time)
        
        assert len(filtered) == 2
        assert reduction > 0
    
    def test_filter_empty_events(self):
        """Test filtering empty event list."""
        
        filtered, reduction = self.filter.filter_events([], self.incident_time)
        
        assert len(filtered) == 0
        assert reduction == 1.0


class TestEntityCorrelator:
    """Test entity correlation stage."""
    
    def setup_method(self):
        self.correlator = EntityCorrelator()
    
    def test_correlate_events_by_entity(self):
        """Test correlating events by entity key."""
        
        events = [
            {
                'user': 'alice',
                'host': 'host1',
                'process': 'explorer.exe',
                'action_type': 'execute',
                'timestamp': '2026-08-10T12:00:00Z'
            },
            {
                'user': 'alice',
                'host': 'host1',
                'process': 'explorer.exe',
                'action_type': 'execute',
                'timestamp': '2026-08-10T12:05:00Z'
            },
            {
                'user': 'bob',
                'host': 'host2',
                'process': 'cmd.exe',
                'action_type': 'execute',
                'timestamp': '2026-08-10T12:10:00Z'
            }
        ]
        
        correlated, reduction = self.correlator.correlate_events(events)
        
        assert len(correlated) == 2  # Two unique entity groups
        assert reduction > 0
        assert correlated[0].compression_ratio > 1
    
    def test_correlate_empty_events(self):
        """Test correlating empty event list."""
        
        correlated, reduction = self.correlator.correlate_events([])
        
        assert len(correlated) == 0
        assert reduction == 1.0


class TestBehavioralFilter:
    """Test behavioral anomaly filtering stage."""
    
    def setup_method(self):
        self.filter = BehavioralFilter(contamination=0.1)
    
    def test_filter_anomalies(self):
        """Test filtering anomalous events."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 9, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice',
                action='login',
                confidence=0.9
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 3, 0, 0),  # Unusual time
                event_type='login',
                entity_type='user',
                entity_id='alice',
                action='login',
                confidence=0.9
            )
        ]
        
        filtered, reduction = self.filter.filter_anomalies(events)
        
        assert len(filtered) <= len(events)
    
    def test_filter_empty_events(self):
        """Test filtering empty event list."""
        
        filtered, reduction = self.filter.filter_anomalies([])
        
        assert len(filtered) == 0
        assert reduction == 1.0


class TestEventDeduplicator:
    """Test event deduplication stage."""
    
    def setup_method(self):
        self.deduplicator = EventDeduplicator()
    
    def test_deduplicate_identical_events(self):
        """Test deduplicating identical events."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 12, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 12, 5, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9
            )
        ]
        
        deduplicated, reduction = self.deduplicator.deduplicate(events)
        
        assert len(deduplicated) == 1
        assert reduction > 0


class TestGraphAnalyzer:
    """Test graph-based relationship analysis."""
    
    def setup_method(self):
        self.analyzer = GraphAnalyzer()
    
    def test_analyze_relationships(self):
        """Test analyzing entity relationships."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 12, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 12, 1, 0),
                event_type='execute',
                entity_type='process',
                entity_id='alice@host2',
                action='execute',
                confidence=0.9
            )
        ]
        
        patterns, reduction = self.analyzer.analyze_relationships(events)
        
        assert isinstance(patterns, list)
    
    def test_find_lateral_movement(self):
        """Test detecting lateral movement patterns."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 12, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 12, 1, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host2',
                action='login',
                confidence=0.9
            )
        ]
        
        patterns, _ = self.analyzer.analyze_relationships(events)
        
        lateral_movement = [p for p in patterns if p['type'] == 'lateral_movement']
        assert len(lateral_movement) > 0


class TestRiskScorer:
    """Test risk scoring stage."""
    
    def setup_method(self):
        self.scorer = RiskScorer()
    
    def test_score_risks(self):
        """Test scoring events by risk."""
        
        events = [
            CorrelatedEvent(
                event_id='e1',
                timestamp=datetime(2026, 8, 10, 12, 0, 0),
                event_type='login',
                entity_type='user',
                entity_id='alice@host1',
                action='login',
                confidence=0.9,
                compression_ratio=5
            ),
            CorrelatedEvent(
                event_id='e2',
                timestamp=datetime(2026, 8, 10, 12, 1, 0),
                event_type='privilege_escalation',
                entity_type='process',
                entity_id='alice@host1',
                action='sudo',
                confidence=0.9,
                compression_ratio=10
            )
        ]
        
        patterns = [
            {'type': 'privilege_escalation', 'confidence': 0.85}
        ]
        
        scored = self.scorer.score_risks(events, patterns)
        
        assert len(scored) <= len(events)
        assert all(e.risk_score > 0 for e in scored)


class TestCorrelationEngine:
    """Test complete correlation & compression pipeline."""
    
    @pytest.mark.asyncio
    async def test_compress_events_complete_pipeline(self):
        """Test complete event compression pipeline."""
        
        engine = CorrelationEngine()
        
        raw_events = [
            {
                'timestamp': '2026-08-10T12:00:00Z',
                'event_type': 'login',
                'user': 'alice',
                'host': 'host1',
                'process': 'explorer.exe',
                'action': 'login'
            },
            {
                'timestamp': '2026-08-10T12:01:00Z',
                'event_type': 'process_execution',
                'user': 'alice',
                'host': 'host1',
                'process': 'cmd.exe',
                'action': 'execute'
            },
            {
                'timestamp': '2026-08-10T12:02:00Z',
                'event_type': 'file_access',
                'user': 'alice',
                'host': 'host1',
                'process': 'cmd.exe',
                'action': 'file_access'
            }
        ]
        
        incident_time = datetime(2026, 8, 10, 12, 0, 0)
        
        package = await engine.compress_events(
            raw_events=raw_events,
            incident_time=incident_time,
            investigation_id='inv-001'
        )
        
        assert package.investigation_id == 'inv-001'
        assert package.original_event_count == 3
        assert package.compressed_event_count <= 3
        assert package.compression_ratio >= 1.0
        assert len(package.timeline) > 0
        assert package.confidence >= 0.0 and package.confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_compress_empty_events(self):
        """Test compression with empty events."""
        
        engine = CorrelationEngine()
        incident_time = datetime(2026, 8, 10, 12, 0, 0)
        
        package = await engine.compress_events(
            raw_events=[],
            incident_time=incident_time,
            investigation_id='inv-002'
        )
        
        assert package.original_event_count == 0
        assert package.compressed_event_count == 0
    
    @pytest.mark.asyncio
    async def test_compression_ratio_calculation(self):
        """Test that compression ratio is calculated correctly."""
        
        engine = CorrelationEngine()
        
        # Create 100 similar events
        raw_events = [
            {
                'timestamp': f'2026-08-10T12:{i % 60:02d}:00Z',
                'event_type': 'login',
                'user': 'alice',
                'host': 'host1',
                'process': 'explorer.exe',
                'action': 'login'
            }
            for i in range(100)
        ]
        
        incident_time = datetime(2026, 8, 10, 12, 0, 0)
        
        package = await engine.compress_events(
            raw_events=raw_events,
            incident_time=incident_time,
            investigation_id='inv-003'
        )
        
        # Should achieve significant compression
        assert package.compression_ratio > 1.0
        assert package.compressed_event_count < package.original_event_count


class TestIntegration:
    """Integration tests for Phase 2."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_correlation_pipeline(self):
        """Test end-to-end correlation pipeline with realistic data."""
        
        engine = CorrelationEngine()
        
        # Simulate ransomware attack timeline
        raw_events = [
            # Initial access
            {'timestamp': '2026-08-10T08:00:00Z', 'event_type': 'login', 
             'user': 'attacker', 'host': 'compromised_host', 'action': 'failed_login'},
            {'timestamp': '2026-08-10T08:05:00Z', 'event_type': 'login',
             'user': 'attacker', 'host': 'compromised_host', 'action': 'failed_login'},
            {'timestamp': '2026-08-10T08:10:00Z', 'event_type': 'login',
             'user': 'attacker', 'host': 'compromised_host', 'action': 'successful_login'},
            
            # Privilege escalation
            {'timestamp': '2026-08-10T08:15:00Z', 'event_type': 'process',
             'user': 'attacker', 'host': 'compromised_host', 'action': 'sudo'},
            
            # Lateral movement
            {'timestamp': '2026-08-10T08:20:00Z', 'event_type': 'network',
             'user': 'attacker', 'host': 'compromised_host', 'action': 'connect'},
            
            # Data exfiltration
            {'timestamp': '2026-08-10T08:30:00Z', 'event_type': 'file',
             'user': 'attacker', 'host': 'compromised_host', 'action': 'file_access'},
            
            # Noise events (normal activity)
            *[
                {'timestamp': '2026-08-10T09:00:00Z', 'event_type': 'login',
                 'user': f'user{i}', 'host': 'normal_host', 'action': 'login'}
                for i in range(50)
            ]
        ]
        
        incident_time = datetime(2026, 8, 10, 8, 0, 0)
        
        package = await engine.compress_events(
            raw_events=raw_events,
            incident_time=incident_time,
            investigation_id='ransomware-001'
        )
        
        # Verify compression (entity correlation merges duplicate events)
        assert package.compression_ratio >= 1.0
        assert len(package.detected_patterns) > 0
        assert len(package.timeline) > 0
        
        # Verify attack pattern detection
        pattern_types = [p.get('type') for p in package.detected_patterns]
        assert any(ptype in pattern_types for ptype in 
                  ['credential_compromise', 'privilege_escalation', 'data_exfiltration'])
