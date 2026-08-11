"""Evidence collection API routes."""

from fastapi import APIRouter, HTTPException
from datetime import datetime

from backend.api.schemas import (
    EvidenceCollectionRequest,
    EvidenceCollectionResponse,
    EntityEnrichment,
)
from backend.services.alert_intake import get_alert_intake_service
from backend.services.evidence_collection import get_evidence_orchestrator

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


@router.post("/collect", response_model=EvidenceCollectionResponse)
async def collect_evidence(request: EvidenceCollectionRequest):
    """
    Collect evidence for an alert (autonomous entity expansion).
    
    Args:
        request: Evidence collection request with investigation ID and depth
    
    Returns:
        EvidenceCollectionResponse with collected entities and relationships
    """
    try:
        # Get the alert from intake service
        intake_service = get_alert_intake_service()
        
        # For now, this would be called after getting pending alerts
        # In a real implementation, we'd fetch from DB
        # This is simplified for Phase 1
        
        orchestrator = get_evidence_orchestrator()
        
        return {
            'investigation_id': request.investigation_id,
            'status': 'not_implemented',
            'entities_count': 0,
            'relationships_count': 0,
            'enrichments': [],
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evidence collection failed: {str(e)}")


@router.get("/stats")
async def get_evidence_stats():
    """Get evidence collection statistics."""
    orchestrator = get_evidence_orchestrator()
    
    return {
        'collectors_available': len(orchestrator.registry.collectors),
        'max_parallel_tasks': orchestrator.max_parallel_tasks,
        'entity_types': list(orchestrator.registry.collectors.keys()),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    }
