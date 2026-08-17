"""Alert intake service orchestrating normalization and deduplication."""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import uuid4

from backend.models.alert import (
    NormalizedAlert,
    AlertNormalizationResult,
)
from backend.services.alert_normalizer import AlertNormalizerFactory
from backend.services.alert_deduplicator import AlertDeduplicator


class AlertIntakeService:
    """Main service for alert ingestion, normalization, and deduplication."""
    
    def __init__(self):
        self.deduplicator = AlertDeduplicator(window_seconds=1800)  # 30 minutes
    
    async def ingest_alert(self, raw_alert: Dict[str, Any], 
                          source: str) -> Dict[str, Any]:
        """
        Ingest and process a raw alert.
        
        Args:
            raw_alert: Raw alert dictionary from source system
            source: Source identifier (e.g., 'crowdstrike', 'splunk')
        
        Returns:
            Response dict with status, alert details, and investigation ID
        """
        # Get appropriate normalizer
        normalizer = AlertNormalizerFactory.create_normalizer(source)
        if not normalizer:
            return {
                'status': 'error',
                'error': f'Unknown alert source: {source}',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        
        # Normalize alert
        normalization_result = normalizer.normalize(raw_alert)
        if not normalization_result.success:
            return {
                'status': 'error',
                'error': normalization_result.error,
                'warnings': normalization_result.warnings,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        
        normalized_alert = normalization_result.normalized_alert
        
        # Deduplicate
        dedup_result = self.deduplicator.deduplicate(normalized_alert)
        final_alert = dedup_result.normalized_alert
        # Persist to database
        from backend.database.connection import get_db
        from backend.database.postgres import AlertRecord
        import contextlib
        
        with contextlib.closing(next(get_db())) as db:
            db_alert = AlertRecord(
                alert_id=final_alert.alert_id,
                investigation_id=final_alert.investigation_id,
                correlation_id=final_alert.correlation_id,
                source_system=final_alert.source,
                source_name=final_alert.source,
                alert_name=final_alert.title,
                alert_category=final_alert.classification.value if hasattr(final_alert.classification, 'value') else str(final_alert.classification),
                severity=final_alert.severity.value,
                confidence=final_alert.confidence,
                status="pending_evidence_collection",
                primary_entities=[e.dict() for e in final_alert.entities],
                alert_metadata=final_alert.raw_data,
                occurrence_count=final_alert.occurrence_count,
                timestamp_generated=final_alert.timestamp,
                timestamp_received=datetime.utcnow()
            )
            db.add(db_alert)
            db.commit()
        
        return {
            'status': 'deduplicated' if dedup_result.is_duplicate else 'accepted',
            'alert_id': final_alert.alert_id,
            'investigation_id': final_alert.investigation_id,
            'correlation_id': final_alert.correlation_id,
            'occurrence_count': final_alert.occurrence_count,
            'parent_alert_id': dedup_result.parent_alert_id,
            'severity': final_alert.severity.value,
            'source': final_alert.source_name,
            'timestamp_received': final_alert.timestamp_received,
        }
    
    async def ingest_alerts_batch(self, alerts: List[Dict[str, Any]],
                                 source: str) -> List[Dict[str, Any]]:
        """
        Ingest multiple alerts in parallel.
        
        Args:
            alerts: List of raw alert dictionaries
            source: Source identifier
        
        Returns:
            List of response dicts
        """
        tasks = [
            self.ingest_alert(alert, source)
            for alert in alerts
        ]
        return await asyncio.gather(*tasks)
    
    def get_pending_alerts(self) -> List[NormalizedAlert]:
        """Get all alerts currently pending evidence collection."""
        from backend.database.connection import get_db
        from backend.database.postgres import AlertRecord
        import contextlib
        from backend.models.alert import NormalizedAlert
        
        with contextlib.closing(next(get_db())) as db:
            records = db.query(AlertRecord).filter(AlertRecord.status == "pending_evidence_collection").all()
            
            alerts = []
            for record in records:
                # Reconstruct NormalizedAlert from DB record (minimal reconstruction for API)
                alert = NormalizedAlert(
                    alert_id=record.alert_id,
                    investigation_id=record.investigation_id,
                    correlation_id=record.correlation_id,
                    source=record.source_system,
                    title=record.alert_name,
                    classification=record.alert_category,
                    severity=record.severity,
                    confidence=record.confidence,
                    entities=record.primary_entities or [],
                    raw_data=record.alert_metadata,
                    timestamp=record.timestamp_generated
                )
                alerts.append(alert)
                
                # Mark them as picked up so they don't get fetched again continuously
                # (In a real system this would be a transaction or locked queue)
                record.status = "in_progress"
            
            if records:
                db.commit()
                
        return alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get intake service statistics."""
        return {
            'tracked_alerts': self.deduplicator.get_alert_count(),
            'pending_evidence_collection': 0,
            'dedup_window_seconds': self.deduplicator.window_seconds,
        }
    
    def cleanup(self) -> int:
        """Clean up expired alerts from deduplication cache."""
        return self.deduplicator.cleanup_expired()


# Global singleton instance
_intake_service: Optional[AlertIntakeService] = None


def get_alert_intake_service() -> AlertIntakeService:
    """Get or create the alert intake service singleton."""
    global _intake_service
    if _intake_service is None:
        _intake_service = AlertIntakeService()
    return _intake_service
