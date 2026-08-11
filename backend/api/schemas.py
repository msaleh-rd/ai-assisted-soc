"""Pydantic schemas for API requests/responses."""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime


class RawAlertRequest(BaseModel):
    """Request body for alert ingestion."""
    source: str = Field(..., description="Alert source (e.g., 'crowdstrike', 'splunk')")
    raw_alert: Dict[str, Any] = Field(..., description="Raw alert data from source system")


class BatchAlertRequest(BaseModel):
    """Request body for batch alert ingestion."""
    source: str
    alerts: List[Dict[str, Any]]


class AlertResponse(BaseModel):
    """Response for alert ingestion."""
    status: str
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None
    correlation_id: Optional[str] = None
    occurrence_count: Optional[int] = None
    parent_alert_id: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    error: Optional[str] = None
    timestamp_received: Optional[str] = None


class PendingAlertsResponse(BaseModel):
    """Response for pending alerts for evidence collection."""
    investigation_id: str
    alert_id: str
    alert_name: str
    severity: str
    source_name: str
    primary_entities: Dict[str, Any]


class EvidenceCollectionRequest(BaseModel):
    """Request to collect evidence for an alert."""
    investigation_id: str
    max_depth: int = Field(default=2, ge=1, le=5)


class EntityEnrichment(BaseModel):
    """Enrichment data for an entity."""
    entity_id: str
    entity_type: str
    enrichment_data: Dict[str, Any]
    threat_intel: Dict[str, Any]
    risk_score: float


class EvidenceCollectionResponse(BaseModel):
    """Response from evidence collection."""
    investigation_id: str
    status: str
    entities_count: int
    relationships_count: int
    enrichments: List[EntityEnrichment]
    timestamp: str


class InvestigationContextResponse(BaseModel):
    """Complete investigation context."""
    investigation_id: str
    alert_id: str
    entities: Dict[str, Any]
    relationships: List[Dict[str, Any]]
    enrichment_data: Dict[str, Any]
    timestamp: str


class ServiceStatsResponse(BaseModel):
    """Service statistics."""
    tracked_alerts: int
    pending_evidence_collection: int
    dedup_window_seconds: int
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
