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
        self.alert_queue: List[NormalizedAlert] = []
    
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
        
        # Queue for evidence collection
        self.alert_queue.append(final_alert)
        
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
        """Get alerts pending evidence collection."""
        alerts = self.alert_queue[:]
        self.alert_queue.clear()
        return alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get intake service statistics."""
        return {
            'tracked_alerts': self.deduplicator.get_alert_count(),
            'pending_evidence_collection': len(self.alert_queue),
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
