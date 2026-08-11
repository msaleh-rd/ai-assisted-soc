"""Phase 3 API Routes - RCA, Response, Reports, and Incident Management

Endpoints for:
1. Root cause analysis
2. Response execution
3. Adaptive investigation
4. Report generation
5. Incident lifecycle management
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime
import uuid

from backend.services.rca_engine import RCAEngineIntegration, ConfidenceLevel
from backend.services.response_orchestration import (
    ResponseOrchestrator,
    AdaptiveInvestigationManager,
    IncidentLifecycleManager
)
from backend.services.report_generation import ReportGenerator, ReportType

# Data models
class RCARequest(BaseModel):
    """Request to perform root cause analysis."""
    investigation_id: str
    package_id: str


class ResponseExecutionRequest(BaseModel):
    """Request to execute response plan."""
    investigation_id: str
    rca_id: str
    auto_approve: bool = False


class AdaptiveInvestigationRequest(BaseModel):
    """Request to run adaptive investigation loop."""
    investigation_id: str
    rca_id: str
    confidence_threshold: float = 0.7
    max_iterations: int = 3


class ReportGenerationRequest(BaseModel):
    """Request to generate reports."""
    incident_id: str
    report_types: List[str] = ["executive_summary", "technical_analysis"]


# Responses
class RCAResponse(BaseModel):
    """RCA analysis response."""
    rca_id: str
    investigation_id: str
    root_cause_service: str
    confidence: float
    attack_type: str
    attack_phases: int
    impacted_assets: int
    recommendations_count: int
    requires_escalation: bool
    status: str


class ResponseExecutionResponse(BaseModel):
    """Response execution summary."""
    execution_id: str
    status: str
    actions_executed: int
    actions_failed: int
    success_rate: float
    duration_seconds: int


class IncidentResponse(BaseModel):
    """Incident details."""
    incident_id: str
    status: str
    severity: str
    created_at: str
    actions_executed: int
    actions_pending: int


class ReportResponse(BaseModel):
    """Report generation response."""
    report_id: str
    report_type: str
    incident_id: str
    title: str
    generated_at: str


# Router
router = APIRouter(prefix="/api/v3/rca", tags=["Phase 3 - RCA & Response"])

# Service instances
rca_engine = RCAEngineIntegration()
response_orchestrator = ResponseOrchestrator(approval_required=False)
adaptive_manager = AdaptiveInvestigationManager()
incident_manager = IncidentLifecycleManager()
report_generator = ReportGenerator()

# In-memory storage (would be database in production)
rca_results: Dict[str, Any] = {}
incidents_created: Dict[str, Dict] = {}


@router.post("/analyze", response_model=RCAResponse)
async def analyze_investigation(request: RCARequest):
    """
    Perform root cause analysis on investigation package.
    
    Analyzes investigation package and produces:
    - Root cause identification
    - Confidence scoring
    - Response recommendations
    - Investigation gap identification
    """
    
    try:
        # Retrieve investigation package from Phase 2
        from backend.api.routes.correlation import investigation_packages
        
        if request.package_id not in investigation_packages:
            raise HTTPException(status_code=404, detail="Investigation package not found")
        
        investigation_package = investigation_packages[request.package_id]
        
        # Perform RCA
        rca_result = await rca_engine.analyze_investigation(investigation_package)
        
        # Store result
        rca_results[rca_result.rca_id] = rca_result
        
        return RCAResponse(
            rca_id=rca_result.rca_id,
            investigation_id=rca_result.investigation_id,
            root_cause_service=rca_result.root_cause.root_cause_service,
            confidence=rca_result.root_cause.confidence,
            attack_type=rca_result.root_cause.attack_type,
            attack_phases=len(rca_result.root_cause.temporal_sequence),
            impacted_assets=rca_result.root_cause.estimated_blast_radius,
            recommendations_count=len(rca_result.immediate_actions),
            requires_escalation=rca_result.requires_escalation,
            status="completed"
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/respond", response_model=ResponseExecutionResponse)
async def execute_response(request: ResponseExecutionRequest,
                          background_tasks: BackgroundTasks):
    """
    Execute response plan from RCA result.
    
    Performs:
    - Immediate containment actions
    - Credentials reset
    - Network blocking
    - System isolation
    - Long-term remediation scheduling
    """
    
    try:
        if request.rca_id not in rca_results:
            raise HTTPException(status_code=404, detail="RCA result not found")
        
        rca_result = rca_results[request.rca_id]
        
        # Create incident
        incident_id = await incident_manager.create_incident(rca_result)
        
        # Execute response
        response_summary = await response_orchestrator.execute_response_plan(
            rca_result=rca_result,
            approval_callback=None
        )
        
        # Update incident
        await incident_manager.execute_incident_response(
            incident_id=incident_id,
            orchestrator=response_orchestrator
        )
        
        # Store incident
        incidents_created[incident_id] = {
            'rca_id': request.rca_id,
            'response_summary': response_summary
        }
        
        return ResponseExecutionResponse(
            execution_id=str(uuid.uuid4()),
            status="completed",
            actions_executed=len(response_summary.get('actions_executed', [])),
            actions_failed=len(response_summary.get('actions_failed', [])),
            success_rate=response_summary.get('success_rate', 0.0),
            duration_seconds=int(response_summary.get('duration_seconds', 0))
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/adaptive-loop")
async def run_adaptive_investigation(request: AdaptiveInvestigationRequest):
    """
    Run adaptive investigation loop for low-confidence cases.
    
    If confidence below threshold:
    - Identify evidence gaps
    - Collect additional data
    - Re-analyze with new data
    - Repeat until confidence threshold reached
    """
    
    try:
        if request.rca_id not in rca_results:
            raise HTTPException(status_code=404, detail="RCA result not found")
        
        # Retrieve original investigation package
        from backend.api.routes.correlation import investigation_packages, compressed_packages
        
        rca_result = rca_results[request.rca_id]
        
        # Find investigation package (this is a simplified lookup)
        investigation_package = None
        for pkg in investigation_packages.values():
            if pkg.investigation_id == request.investigation_id:
                investigation_package = pkg
                break
        
        if not investigation_package:
            raise HTTPException(status_code=404, detail="Investigation package not found")
        
        # Run adaptive loop
        improved_result = await adaptive_manager.run_adaptive_loop(
            investigation_package=investigation_package,
            rca_result=rca_result,
            data_collector=_stub_data_collector
        )
        
        # Update stored result
        rca_results[request.rca_id] = improved_result
        
        return {
            'rca_id': request.rca_id,
            'initial_confidence': rca_result.root_cause.confidence,
            'final_confidence': improved_result.root_cause.confidence,
            'iterations_performed': len(adaptive_manager.iterations),
            'confidence_improved': improved_result.root_cause.confidence > rca_result.root_cause.confidence,
            'status': 'completed'
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-reports", response_model=Dict[str, ReportResponse])
async def generate_reports(request: ReportGenerationRequest):
    """
    Generate incident reports.
    
    Supports:
    - Executive Summary
    - Technical Analysis
    - Forensic Report
    - Compliance Report
    - Incident Log
    """
    
    try:
        if request.incident_id not in incidents_created:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        incident_info = incidents_created[request.incident_id]
        rca_result = rca_results.get(incident_info['rca_id'])
        response_summary = incident_info.get('response_summary', {})
        
        if not rca_result:
            raise HTTPException(status_code=404, detail="RCA result not found")
        
        # Generate requested report types
        reports = await report_generator.generate_all_reports(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id=request.incident_id
        )
        
        # Format response
        report_responses = {}
        for report_type, report in reports.items():
            report_responses[report_type] = ReportResponse(
                report_id=report.report_id,
                report_type=report.report_type.value,
                incident_id=report.incident_id,
                title=report.title,
                generated_at=report.generated_at.isoformat()
            )
        
        return report_responses
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rca/{rca_id}")
async def get_rca_result(rca_id: str):
    """Retrieve RCA result details."""
    
    if rca_id not in rca_results:
        raise HTTPException(status_code=404, detail="RCA result not found")
    
    result = rca_results[rca_id]
    
    return {
        'rca_id': rca_id,
        'investigation_id': result.investigation_id,
        'root_cause': {
            'service': result.root_cause.root_cause_service,
            'target_service': result.root_cause.target_service,
            'confidence': result.root_cause.confidence,
            'attack_type': result.root_cause.attack_type,
            'supporting_evidence_count': len(result.root_cause.supporting_evidence),
            'contradicting_evidence_count': len(result.root_cause.contradicting_evidence)
        },
        'confidence_level': result.confidence_level.value,
        'attack_chain': result.attack_chain_description,
        'mitre_tactics': result.mitre_tactics,
        'mitre_techniques': result.mitre_techniques,
        'immediate_actions': [
            {
                'action': a.action.value,
                'target': a.target,
                'priority': a.priority
            }
            for a in result.immediate_actions
        ],
        'investigation_gaps': [
            {
                'gap_type': g.gap_type,
                'severity': g.severity,
                'affected_entity': g.affected_entity
            }
            for g in result.investigation_gaps
        ],
        'requires_escalation': result.requires_escalation,
        'created_at': result.created_at.isoformat()
    }


@router.get("/incident/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str):
    """Retrieve incident details."""
    
    incident = incident_manager.get_incident(incident_id)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return IncidentResponse(
        incident_id=incident_id,
        status=incident['status'],
        severity=incident.get('severity', 'unknown'),
        created_at=incident['created_at'].isoformat(),
        actions_executed=len(incident.get('actions_executed', [])),
        actions_pending=incident.get('actions_pending', 0)
    )


@router.get("/incidents")
async def list_incidents(status: Optional[str] = None):
    """List incidents, optionally filtered by status."""
    
    incidents = incident_manager.list_incidents(status=status)
    
    return {
        'total': len(incidents),
        'incidents': [
            {
                'incident_id': i['id'],
                'status': i['status'],
                'severity': i.get('severity', 'unknown'),
                'created_at': i['created_at'].isoformat(),
                'closed_at': i['closed_at'].isoformat() if i['closed_at'] else None,
                'actions_executed': len(i.get('actions_executed', []))
            }
            for i in incidents
        ]
    }


@router.post("/close-incident")
async def close_incident(incident_id: str, closure_notes: str,
                        lessons_learned: Optional[List[str]] = None):
    """Close incident and record lessons learned."""
    
    result = await incident_manager.close_incident(
        incident_id=incident_id,
        closure_notes=closure_notes,
        lessons_learned=lessons_learned
    )
    
    return result


@router.get("/report/{report_id}")
async def get_report(report_id: str, format: str = "json"):
    """Retrieve report."""
    
    report = report_generator.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if format == "json":
        return report_generator.export_report_json(report_id)
    elif format == "text":
        return {
            'report_id': report_id,
            'type': report.report_type.value,
            'title': report.title,
            'body': report.body,
            'recommendations': report.recommendations
        }
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    
    return {
        'status': 'healthy',
        'service': 'Phase 3 - RCA & Response',
        'rca_results_count': len(rca_results),
        'incidents_count': len(incidents_created),
        'timestamp': datetime.now().isoformat()
    }


# Helper function
async def _stub_data_collector(query: Dict[str, Any]) -> List[Dict]:
    """Stub data collector for adaptive investigation."""
    
    # In production, would query actual data sources
    return [
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'collected',
            'entity': query.get('entity', 'unknown'),
            'risk_score': 0.5
        }
    ]
