"""Phase 3 Tests - RCA Engine, Response Orchestration, Adaptive Investigation, Reports

Comprehensive test suite for Phase 3 components.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

from backend.services.rca_engine import (
    RCAEngineIntegration, ConfidenceLevel, ResponseAction,
    RootCauseAnalysis, ResponseRecommendation, AdaptiveInvestigationGap, RCAResult
)
from backend.services.response_orchestration import (
    ResponseOrchestrator, AdaptiveInvestigationManager, IncidentLifecycleManager,
    ActionStatus, AdaptiveLoopPhase
)
from backend.services.report_generation import ReportGenerator, ReportType


# Fixtures
@pytest.fixture
def mock_investigation_package():
    """Mock investigation package from Phase 2."""
    return Mock(
        investigation_id="inv-001",
        package_id="pkg-001",
        impacted_assets=["database-prod", "api-server-1", "cache-redis"],
        suspected_attack_types=["credential_compromise", "lateral_movement"],
        overall_confidence=0.65,
        evidence_quality_score=0.7,
        raw_events=[
            {
                'timestamp': '2026-08-11T10:00:00Z',
                'entity': 'database-prod',
                'action': 'failed_login_attempts',
                'risk_score': 0.9
            },
            {
                'timestamp': '2026-08-11T10:05:00Z',
                'entity': 'api-server-1',
                'action': 'successful_login',
                'risk_score': 0.85
            },
            {
                'timestamp': '2026-08-11T10:10:00Z',
                'entity': 'cache-redis',
                'action': 'data_exfiltration',
                'risk_score': 0.92
            }
        ],
        timeline=[
            {'timestamp': '2026-08-11T10:00:00Z', 'action': 'failed_login_attempts', 'entity': 'database-prod'},
            {'timestamp': '2026-08-11T10:05:00Z', 'action': 'successful_login', 'entity': 'api-server-1'},
            {'timestamp': '2026-08-11T10:10:00Z', 'action': 'lateral_movement', 'entity': 'cache-redis'},
        ],
        entity_graph={
            'database-prod': ['api-server-1'],
            'api-server-1': ['cache-redis'],
            'cache-redis': []
        },
        attack_phases=[
            {'phase': 'credential_access', 'confidence': 0.9},
            {'phase': 'lateral_movement', 'confidence': 0.8}
        ]
    )


@pytest.fixture
def rca_engine():
    """RCA engine instance."""
    return RCAEngineIntegration()


@pytest.fixture
def response_orchestrator():
    """Response orchestrator instance."""
    return ResponseOrchestrator(approval_required=False)


@pytest.fixture
def adaptive_manager():
    """Adaptive investigation manager."""
    return AdaptiveInvestigationManager(max_iterations=3, confidence_threshold=0.7)


@pytest.fixture
def incident_manager():
    """Incident lifecycle manager."""
    return IncidentLifecycleManager()


@pytest.fixture
def report_generator():
    """Report generator instance."""
    return ReportGenerator()


# Tests for RCA Engine
class TestRCAEngineIntegration:
    """Test RCA engine integration."""
    
    @pytest.mark.asyncio
    async def test_analyze_investigation_complete(self, rca_engine, mock_investigation_package):
        """Test complete RCA analysis flow."""
        
        result = await rca_engine.analyze_investigation(mock_investigation_package)
        
        assert isinstance(result, RCAResult)
        assert result.investigation_id == "inv-001"
        assert result.root_cause.confidence > 0
        assert len(result.immediate_actions) > 0
        assert result.created_at is not None
    
    @pytest.mark.asyncio
    async def test_rca_result_structure(self, rca_engine, mock_investigation_package):
        """Test RCA result has all required fields."""
        
        result = await rca_engine.analyze_investigation(mock_investigation_package)
        
        # Check root cause
        assert result.root_cause.target_service
        assert result.root_cause.root_cause_service
        assert 0 <= result.root_cause.confidence <= 1.0
        
        # Check recommendations
        assert len(result.immediate_actions) > 0
        for action in result.immediate_actions:
            assert isinstance(action, ResponseRecommendation)
            assert action.action in ResponseAction
            assert action.priority in ["critical", "high", "medium", "low"]
        
        # Check reporting
        assert len(result.executive_summary) > 0
        assert len(result.technical_narrative) > 0
        assert len(result.attack_chain_description) > 0
        assert len(result.mitre_tactics) > 0
        assert len(result.mitre_techniques) > 0
    
    @pytest.mark.asyncio
    async def test_confidence_level_mapping(self, rca_engine):
        """Test confidence level determination."""
        
        levels = [
            (0.95, ConfidenceLevel.VERY_HIGH),
            (0.8, ConfidenceLevel.HIGH),
            (0.6, ConfidenceLevel.MEDIUM),
            (0.4, ConfidenceLevel.LOW),
            (0.2, ConfidenceLevel.VERY_LOW)
        ]
        
        for confidence, expected_level in levels:
            level = rca_engine._determine_confidence_level(confidence)
            assert level == expected_level
    
    @pytest.mark.asyncio
    async def test_response_recommendations_generated(self, rca_engine, mock_investigation_package):
        """Test response recommendations are generated correctly."""
        
        result = await rca_engine.analyze_investigation(mock_investigation_package)
        
        # Should have recommendations
        assert len(result.immediate_actions) > 0
        
        # Isolation should be priority 1
        isolation_actions = [a for a in result.immediate_actions if a.action == ResponseAction.ISOLATE_HOST]
        assert len(isolation_actions) > 0
        assert isolation_actions[0].priority == "critical"
    
    @pytest.mark.asyncio
    async def test_investigation_gaps_identified(self, rca_engine, mock_investigation_package):
        """Test investigation gaps are identified."""
        
        result = await rca_engine.analyze_investigation(mock_investigation_package)
        
        # Should identify gaps for low confidence
        if result.root_cause.confidence < 0.7:
            assert len(result.investigation_gaps) > 0
            for gap in result.investigation_gaps:
                assert isinstance(gap, AdaptiveInvestigationGap)
                assert gap.gap_type in ["missing_logs", "incomplete_timeline", "uncertain_correlation"]


# Tests for Response Orchestration
class TestResponseOrchestrator:
    """Test response orchestration."""
    
    @pytest.mark.asyncio
    async def test_execute_response_plan(self, response_orchestrator, 
                                        rca_engine, mock_investigation_package):
        """Test full response plan execution."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        response_summary = await response_orchestrator.execute_response_plan(rca_result)
        
        assert response_summary['status'] == 'completed'
        assert response_summary['total_actions'] > 0
        assert 0 <= response_summary['success_rate'] <= 1.0
        assert 'started_at' in response_summary
        assert 'completed_at' in response_summary
    
    @pytest.mark.asyncio
    async def test_action_execution_logging(self, response_orchestrator):
        """Test action execution is logged."""
        
        initial_log_count = len(response_orchestrator.execution_log)
        
        # Execute a test action
        action = ResponseRecommendation(
            action=ResponseAction.ISOLATE_HOST,
            priority="critical",
            target="test-host",
            description="Test isolation",
            prerequisites=["test"],
            estimated_time_minutes=5,
            success_criteria=["test"],
            rollback_steps=["test"],
            business_impact="test"
        )
        
        result = await response_orchestrator._execute_action(action, None, "test")
        
        assert result['success'] == True
        assert len(response_orchestrator.execution_log) > initial_log_count
    
    @pytest.mark.asyncio
    async def test_action_types_execute(self, response_orchestrator):
        """Test all action types execute without error."""
        
        action_types = [
            ResponseAction.ISOLATE_HOST,
            ResponseAction.RESET_CREDENTIALS,
            ResponseAction.BLOCK_IP,
            ResponseAction.BLOCK_DOMAIN,
            ResponseAction.KILL_PROCESS,
            ResponseAction.ENABLE_MFA
        ]
        
        for action_type in action_types:
            action = ResponseRecommendation(
                action=action_type,
                priority="high",
                target=f"test-target-{action_type.value}",
                description=f"Test {action_type.value}",
                prerequisites=[],
                estimated_time_minutes=5,
                success_criteria=[],
                rollback_steps=[],
                business_impact="None"
            )
            
            result = await response_orchestrator._execute_action(action, None, "test")
            assert result['success'] == True


# Tests for Adaptive Investigation
class TestAdaptiveInvestigationManager:
    """Test adaptive investigation loops."""
    
    @pytest.mark.asyncio
    async def test_run_adaptive_loop(self, adaptive_manager, mock_investigation_package,
                                     rca_engine):
        """Test adaptive investigation loop."""
        
        # Create low-confidence RCA result
        low_conf_result = Mock(
            root_cause=Mock(confidence=0.5),
            investigation_gaps=[
                Mock(
                    gap_type="missing_logs",
                    recommended_query={"type": "test"},
                    affected_entity="test"
                )
            ]
        )
        
        # Mock data collector
        async def mock_collector(query):
            return [{'timestamp': datetime.now().isoformat(), 'event_type': 'test'}]
        
        result = await adaptive_manager.run_adaptive_loop(
            investigation_package=mock_investigation_package,
            rca_result=low_conf_result,
            data_collector=mock_collector
        )
        
        # Should have attempted iterations
        assert len(adaptive_manager.iterations) > 0
    
    @pytest.mark.asyncio
    async def test_max_iterations_respected(self, adaptive_manager, mock_investigation_package):
        """Test max iterations limit is respected."""
        
        low_conf_result = Mock(
            root_cause=Mock(confidence=0.1),  # Very low confidence
            investigation_gaps=[Mock(gap_type="test", recommended_query={}, affected_entity="test")]
        )
        
        async def mock_collector(query):
            return []
        
        await adaptive_manager.run_adaptive_loop(
            investigation_package=mock_investigation_package,
            rca_result=low_conf_result,
            data_collector=mock_collector
        )
        
        # Should not exceed max_iterations
        assert len(adaptive_manager.iterations) <= adaptive_manager.max_iterations


# Tests for Incident Lifecycle
class TestIncidentLifecycleManager:
    """Test incident lifecycle management."""
    
    @pytest.mark.asyncio
    async def test_create_incident(self, incident_manager, rca_engine, 
                                  mock_investigation_package):
        """Test incident creation."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        incident_id = await incident_manager.create_incident(rca_result)
        
        assert incident_id.startswith("INC-")
        assert incident_id in incident_manager.incidents
        
        incident = incident_manager.get_incident(incident_id)
        assert incident['status'] == 'open'
        assert incident['severity'] in ['critical', 'high', 'medium', 'low']
    
    @pytest.mark.asyncio
    async def test_incident_response_execution(self, incident_manager, response_orchestrator,
                                               rca_engine, mock_investigation_package):
        """Test executing response for incident."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        incident_id = await incident_manager.create_incident(rca_result)
        
        response_summary = await incident_manager.execute_incident_response(
            incident_id=incident_id,
            orchestrator=response_orchestrator
        )
        
        assert len(response_summary.get('actions_executed', [])) >= 0
        
        incident = incident_manager.get_incident(incident_id)
        assert incident['status'] == 'responding'
    
    @pytest.mark.asyncio
    async def test_close_incident(self, incident_manager, rca_engine,
                                 mock_investigation_package):
        """Test closing incident."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        incident_id = await incident_manager.create_incident(rca_result)
        
        closure_result = await incident_manager.close_incident(
            incident_id=incident_id,
            closure_notes="Incident resolved successfully",
            lessons_learned=["Improve monitoring", "Update runbooks"]
        )
        
        assert closure_result['status'] == 'closed'
        
        incident = incident_manager.get_incident(incident_id)
        assert incident['status'] == 'closed'
        assert incident['closure_notes'] == "Incident resolved successfully"
        assert len(incident['lessons_learned']) == 2


# Tests for Report Generation
class TestReportGenerator:
    """Test report generation."""
    
    @pytest.mark.asyncio
    async def test_generate_executive_summary(self, report_generator, rca_engine,
                                            mock_investigation_package):
        """Test executive summary report generation."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        response_summary = {'actions_executed': []}
        
        report = await report_generator.generate_executive_summary(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id="INC-001"
        )
        
        assert report.report_type == ReportType.EXECUTIVE_SUMMARY
        assert "Incident Summary" in report.body or "INCIDENT SUMMARY" in report.body.upper()
        assert len(report.findings) > 0
    
    @pytest.mark.asyncio
    async def test_generate_technical_analysis(self, report_generator, rca_engine,
                                              mock_investigation_package):
        """Test technical analysis report generation."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        response_summary = {}
        
        report = await report_generator.generate_technical_analysis(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id="INC-001"
        )
        
        assert report.report_type == ReportType.TECHNICAL_ANALYSIS
        assert "MITRE" in report.body or "mitre" in report.body.lower()
    
    @pytest.mark.asyncio
    async def test_generate_forensic_report(self, report_generator, rca_engine,
                                           mock_investigation_package):
        """Test forensic report generation."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        
        report = await report_generator.generate_forensic_report(
            rca_result=rca_result,
            incident_id="INC-001"
        )
        
        assert report.report_type == ReportType.FORENSIC_REPORT
        assert "FORENSIC" in report.body.upper() or "forensic" in report.body.lower()
    
    @pytest.mark.asyncio
    async def test_generate_compliance_report(self, report_generator, rca_engine,
                                            mock_investigation_package):
        """Test compliance report generation."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        
        report = await report_generator.generate_compliance_report(
            rca_result=rca_result,
            incident_id="INC-001"
        )
        
        assert report.report_type == ReportType.COMPLIANCE_REPORT
        assert "COMPLIANCE" in report.body.upper() or "REGULATORY" in report.body.upper()
    
    @pytest.mark.asyncio
    async def test_generate_all_reports(self, report_generator, rca_engine,
                                       mock_investigation_package):
        """Test generating all report types."""
        
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        response_summary = {'actions_executed': []}
        
        reports = await report_generator.generate_all_reports(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id="INC-001"
        )
        
        assert 'executive' in reports
        assert 'technical' in reports
        assert 'forensic' in reports
        assert 'compliance' in reports
        assert 'log' in reports


# Integration Tests
class TestPhase3Integration:
    """End-to-end Phase 3 integration tests."""
    
    @pytest.mark.asyncio
    async def test_complete_incident_flow(self, rca_engine, response_orchestrator,
                                         incident_manager, report_generator,
                                         mock_investigation_package):
        """Test complete incident detection to closure flow."""
        
        # 1. RCA Analysis
        rca_result = await rca_engine.analyze_investigation(mock_investigation_package)
        assert rca_result.root_cause.confidence > 0
        
        # 2. Create Incident
        incident_id = await incident_manager.create_incident(rca_result)
        assert incident_id in incident_manager.incidents
        
        # 3. Execute Response
        response_summary = await incident_manager.execute_incident_response(
            incident_id=incident_id,
            orchestrator=response_orchestrator
        )
        assert response_summary['success_rate'] >= 0
        
        # 4. Generate Reports
        reports = await report_generator.generate_all_reports(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id=incident_id
        )
        assert len(reports) == 5
        
        # 5. Close Incident
        closure_result = await incident_manager.close_incident(
            incident_id=incident_id,
            closure_notes="Completed integration test"
        )
        assert closure_result['status'] == 'closed'
        
        # Verify final state
        incident = incident_manager.get_incident(incident_id)
        assert incident['status'] == 'closed'


# Run with: pytest backend/tests/test_phase3.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
