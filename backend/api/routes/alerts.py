"""Alert intake API routes."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List

from backend.api.schemas import (
    RawAlertRequest,
    BatchAlertRequest,
    AlertResponse,
)
from backend.services.alert_intake import get_alert_intake_service

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.post("/ingest", response_model=AlertResponse)
async def ingest_alert(request: RawAlertRequest) -> AlertResponse:
    """
    Ingest a single alert from any supported source.
    
    Args:
        request: Alert ingestion request with source and raw alert data
    
    Returns:
        AlertResponse with ingestion status and details
    """
    service = get_alert_intake_service()
    
    try:
        result = await service.ingest_alert(request.raw_alert, request.source)
        
        if result['status'] == 'error':
            raise HTTPException(
                status_code=400,
                detail=result.get('error', 'Alert ingestion failed')
            )
        
        return AlertResponse(**result)
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.post("/ingest-batch", response_model=List[AlertResponse])
async def ingest_alerts_batch(request: BatchAlertRequest) -> List[AlertResponse]:
    """
    Ingest multiple alerts in batch from same source.
    
    Args:
        request: Batch alert ingestion with source and alert list
    
    Returns:
        List of AlertResponse objects
    """
    service = get_alert_intake_service()
    
    try:
        results = await service.ingest_alerts_batch(request.alerts, request.source)
        
        responses = []
        for result in results:
            if result.get('status') == 'error':
                responses.append(AlertResponse(
                    status='error',
                    error=result.get('error'),
                ))
            else:
                responses.append(AlertResponse(**result))
        
        return responses
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/pending", tags=["alerts"])
async def get_pending_alerts():
    """
    Get alerts pending evidence collection.
    
    This endpoint is called by the evidence collection service
    to get the next batch of alerts to process.
    
    Returns:
        List of pending alerts
    """
    service = get_alert_intake_service()
    alerts = service.get_pending_alerts()
    
    return {
        'count': len(alerts),
        'alerts': [alert.to_dict() for alert in alerts]
    }


@router.get("/stats", tags=["alerts"])
async def get_alert_stats():
    """Get alert intake service statistics."""
    service = get_alert_intake_service()
    stats = service.get_stats()
    
    from datetime import datetime
    stats['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    
    return stats


@router.post("/cleanup", tags=["alerts"])
async def cleanup_expired_alerts():
    """
    Clean up alerts outside the deduplication window.
    
    Can be called periodically (e.g., via scheduler) to free memory.
    
    Returns:
        Count of cleaned up alerts
    """
    service = get_alert_intake_service()
    count = service.cleanup()
    
    return {
        'cleaned_up': count,
        'status': 'success'
    }
