"""Phase 2 API Routes - Correlation & Compression & Investigation Packages

Endpoints for:
1. Triggering correlation compression
2. Building investigation packages
3. Querying compressed data
4. RCA engine preparation
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
import uuid

from backend.services.correlation_engine import CorrelationEngine, CompressedPackage
from backend.services.investigation_builder import (
    InvestigationPackageBuilder,
    PackageType,
    InvestigationPackage
)

# Data models for API
class CorrelationRequest(BaseModel):
    """Request to correlate and compress events."""
    investigation_id: str
    alert_id: str
    events: List[Dict]
    incident_time: str


class CorrelationResponse(BaseModel):
    """Response with compressed events."""
    investigation_id: str
    original_event_count: int
    compressed_event_count: int
    compression_ratio: float
    timeline_events: int
    detected_patterns: int
    risk_score: float
    status: str


class InvestigationPackageRequest(BaseModel):
    """Request to build investigation package."""
    investigation_id: str
    compressed_package_id: str
    package_type: str = "detailed_rca"
    original_alert: Dict


class InvestigationPackageResponse(BaseModel):
    """Response with investigation package."""
    package_id: str
    investigation_id: str
    original_alert_id: str
    compression_ratio: float
    selected_event_count: int
    confidence: float
    suspected_attack_types: List[str]
    impacted_assets: int
    immediate_actions: int
    status: str


class CompressionStatsResponse(BaseModel):
    """Statistics about compression pipeline."""
    total_investigations: int
    avg_compression_ratio: float
    avg_timeline_events: int
    total_patterns_detected: int


# Router
router = APIRouter(prefix="/api/v2/correlation", tags=["Phase 2 - Correlation"])

# Service instances
correlation_engine = CorrelationEngine()
package_builder = InvestigationPackageBuilder()

# In-memory storage (would be database in production)
compressed_packages: Dict[str, CompressedPackage] = {}
investigation_packages: Dict[str, InvestigationPackage] = {}
compression_stats = {
    'total_investigations': 0,
    'total_events_compressed': 0,
    'total_events_original': 0,
    'patterns_detected': 0
}


@router.post("/compress", response_model=CorrelationResponse)
async def compress_events(request: CorrelationRequest, background_tasks: BackgroundTasks):
    """
    Compress events through 7-stage correlation pipeline.
    
    Stages:
    1. Temporal Filter (80-90% reduction)
    2. Entity Correlation (50-70% reduction)
    3. Behavioral Filter (60-80% reduction)
    4. Deduplication (30-40% reduction)
    5. Graph Analysis (40-60% reduction)
    6. Abstraction (20-40% reduction)
    7. Risk Scoring (40-60% reduction)
    
    Expected result: 1000-10000x event reduction.
    """
    
    try:
        # Parse incident time
        incident_time = datetime.fromisoformat(request.incident_time.replace('Z', '+00:00'))
        
        # Run compression pipeline
        compressed_package = await correlation_engine.compress_events(
            raw_events=request.events,
            incident_time=incident_time,
            investigation_id=request.investigation_id
        )
        
        # Store for later retrieval
        compressed_packages[request.investigation_id] = compressed_package
        
        # Update stats
        compression_stats['total_investigations'] += 1
        compression_stats['total_events_original'] += request.events.__len__()
        compression_stats['total_events_compressed'] += len(compressed_package.events)
        compression_stats['patterns_detected'] += len(compressed_package.detected_patterns)
        
        return CorrelationResponse(
            investigation_id=request.investigation_id,
            original_event_count=len(request.events),
            compressed_event_count=len(compressed_package.events),
            compression_ratio=compressed_package.compression_ratio,
            timeline_events=len(compressed_package.timeline),
            detected_patterns=len(compressed_package.detected_patterns),
            risk_score=compressed_package.risk_score,
            status="completed"
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigate", response_model=InvestigationPackageResponse)
async def build_investigation(request: InvestigationPackageRequest):
    """
    Build investigation package from compressed events.
    
    Performs:
    - Entity graph construction
    - Evidence selection & ranking
    - Attack phase analysis
    - Confidence scoring
    - Immediate action recommendations
    """
    
    try:
        # Get compressed package
        if request.investigation_id not in compressed_packages:
            raise HTTPException(status_code=404, detail="Compressed package not found")
        
        compressed_package = compressed_packages[request.investigation_id]
        
        # Parse package type
        try:
            package_type = PackageType[request.package_type.upper()]
        except KeyError:
            package_type = PackageType.DETAILED_RCA
        
        # Build investigation package
        investigation_package = await package_builder.build_package(
            compressed_package=compressed_package,
            original_alert=request.original_alert,
            package_type=package_type
        )
        
        # Store for later retrieval
        investigation_packages[investigation_package.package_id] = investigation_package
        
        return InvestigationPackageResponse(
            package_id=investigation_package.package_id,
            investigation_id=investigation_package.investigation_id,
            original_alert_id=investigation_package.original_alert_id,
            compression_ratio=investigation_package.compression_ratio,
            selected_event_count=investigation_package.selected_event_count,
            confidence=investigation_package.overall_confidence,
            suspected_attack_types=investigation_package.suspected_attack_types,
            impacted_assets=len(investigation_package.impacted_assets),
            immediate_actions=len(investigation_package.immediate_actions),
            status="completed"
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compressed/{investigation_id}")
async def get_compressed_package(investigation_id: str):
    """Retrieve compressed package details."""
    
    if investigation_id not in compressed_packages:
        raise HTTPException(status_code=404, detail="Package not found")
    
    package = compressed_packages[investigation_id]
    
    return {
        "investigation_id": package.investigation_id,
        "original_event_count": package.original_event_count,
        "compressed_event_count": package.compressed_event_count,
        "compression_ratio": package.compression_ratio,
        "timeline_events": len(package.timeline),
        "detected_patterns": [
            {
                "type": p.get("type"),
                "confidence": p.get("confidence", 0.0),
                "entities": len([e for e in p.get("entities", [])])
            }
            for p in package.detected_patterns
        ],
        "risk_score": package.risk_score,
        "confidence": package.confidence,
        "created_at": package.created_at.isoformat()
    }


@router.get("/package/{package_id}")
async def get_investigation_package(package_id: str):
    """Retrieve investigation package details."""
    
    if package_id not in investigation_packages:
        raise HTTPException(status_code=404, detail="Package not found")
    
    package = investigation_packages[package_id]
    
    return {
        "package_id": package.package_id,
        "investigation_id": package.investigation_id,
        "package_type": package.package_type.value,
        "compression_ratio": package.compression_ratio,
        "selected_event_count": package.selected_event_count,
        "confidence": {
            "overall": package.overall_confidence,
            "evidence_quality": package.evidence_quality_score,
            "timeline_coherence": package.timeline_coherence,
            "pattern_detection": package.attack_pattern_confidence
        },
        "suspected_attack_types": package.suspected_attack_types,
        "attack_phases": [
            {
                "phase": p.get("phase"),
                "event_count": p.get("event_count"),
                "confidence": p.get("confidence")
            }
            for p in package.attack_phases
        ],
        "impacted_assets": package.impacted_assets,
        "immediate_actions": [
            {
                "action": a.get("action"),
                "priority": a.get("priority"),
                "description": a.get("description")
            }
            for a in package.immediate_actions
        ],
        "evidence_gaps": package.evidence_gaps,
        "created_at": package.created_at.isoformat()
    }


@router.get("/stats", response_model=CompressionStatsResponse)
async def get_compression_stats():
    """Get compression pipeline statistics."""
    
    avg_compression = (
        compression_stats['total_events_original'] / 
        max(compression_stats['total_events_compressed'], 1)
    )
    
    avg_timeline = (
        compression_stats['total_events_compressed'] / 
        max(compression_stats['total_investigations'], 1)
    )
    
    return CompressionStatsResponse(
        total_investigations=compression_stats['total_investigations'],
        avg_compression_ratio=avg_compression,
        avg_timeline_events=int(avg_timeline),
        total_patterns_detected=compression_stats['patterns_detected']
    )


@router.get("/timeline/{investigation_id}")
async def get_timeline(investigation_id: str):
    """Get timeline for investigation."""
    
    if investigation_id not in compressed_packages:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    package = compressed_packages[investigation_id]
    
    return {
        "investigation_id": investigation_id,
        "event_count": len(package.timeline),
        "timeline": package.timeline
    }


@router.get("/graph/{investigation_id}")
async def get_attack_graph(investigation_id: str):
    """Get attack graph for investigation."""
    
    if investigation_id not in compressed_packages:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    package = compressed_packages[investigation_id]
    
    return {
        "investigation_id": investigation_id,
        "attack_graph": package.attack_graph,
        "patterns": package.detected_patterns
    }


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    
    return {
        "status": "healthy",
        "service": "Phase 2 - Correlation & Compression",
        "timestamp": datetime.now().isoformat()
    }
