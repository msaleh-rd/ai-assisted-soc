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
from backend.services.entity_risk import entity_risk_tracker, severity_to_risk_score


def _extract_entity_key(entity_value: Any) -> Optional[str]:
    """Best-effort extraction of a stable identifier from a primary_entities value."""
    if isinstance(entity_value, str):
        return entity_value or None
    if isinstance(entity_value, dict):
        for key in ("id", "hostname", "name", "hash", "path"):
            val = entity_value.get(key)
            if val:
                return str(val)
    return None


class AlertIntakeService:
    """Main service for alert ingestion, normalization, and deduplication."""
    
    def __init__(self):
        self.deduplicator = AlertDeduplicator(window_seconds=1800)  # 30 minutes
        self.in_memory_alerts: List[NormalizedAlert] = []
    
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
        # Ingest into memory queue
        self.in_memory_alerts.append(final_alert)
        
        # Persist to database if initialized
        try:
            from backend.database.connection import SessionLocal, get_db
            from backend.database.postgres import AlertRecord
            import contextlib
            
            if SessionLocal is not None:
                with contextlib.closing(next(get_db())) as db:
                    db_alert = AlertRecord(
                        alert_id=final_alert.alert_id,
                        investigation_id=final_alert.investigation_id,
                        correlation_id=final_alert.correlation_id,
                        source_system=final_alert.source_system.value if hasattr(final_alert.source_system, 'value') else str(final_alert.source_system),
                        source_name=final_alert.source_name,
                        alert_name=final_alert.alert_name,
                        alert_category=final_alert.alert_category,
                        severity=final_alert.severity.value if hasattr(final_alert.severity, 'value') else str(final_alert.severity),
                        confidence=final_alert.confidence,
                        status="pending_evidence_collection",
                        primary_entities=final_alert.primary_entities,
                        alert_metadata=final_alert.alert_metadata or {},
                        occurrence_count=final_alert.occurrence_count,
                        timestamp_generated=datetime.fromisoformat(final_alert.timestamp_generated.replace('Z', '+00:00')) if isinstance(final_alert.timestamp_generated, str) else final_alert.timestamp_generated,
                        timestamp_received=datetime.utcnow()
                    )
                    db.add(db_alert)
                    db.commit()
        except Exception:
            pass
        
        # Update per-entity time-decayed cumulative risk and flag any entity
        # that has crossed the auto-promotion threshold (QW-3: Entity-Risk Scoring).
        entity_risk_updates = []
        risk_score = severity_to_risk_score(
            final_alert.severity.value if hasattr(final_alert.severity, 'value') else str(final_alert.severity)
        )
        for entity_type, entity_value in (final_alert.primary_entities or {}).items():
            entity_key = _extract_entity_key(entity_value)
            if not entity_key:
                continue
            update = entity_risk_tracker.record_alert(
                entity_id=f"{entity_type}:{entity_key}",
                entity_type=entity_type,
                alert_id=final_alert.alert_id,
                risk_score=risk_score,
            )
            entity_risk_updates.append({
                'entity_id': update.entity_id,
                'entity_type': update.entity_type,
                'cumulative_risk': round(update.cumulative_risk, 4),
                'promoted': update.promoted,
                'newly_promoted': update.newly_promoted,
            })
        
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
            'entity_risk': entity_risk_updates,
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
        try:
            from backend.database.connection import SessionLocal, get_db
            from backend.database.postgres import AlertRecord
            import contextlib
            from backend.models.alert import NormalizedAlert, AlertSource, AlertSeverity
            
            if SessionLocal is not None:
                with contextlib.closing(next(get_db())) as db:
                    records = db.query(AlertRecord).filter(AlertRecord.status == "pending_evidence_collection").all()
                    
                    alerts = []
                    for record in records:
                        try:
                            source_enum = AlertSource(record.source_system)
                        except ValueError:
                            source_enum = AlertSource.OTHER
                        try:
                            sev_enum = AlertSeverity(record.severity)
                        except ValueError:
                            sev_enum = AlertSeverity.MEDIUM
                            
                        alert = NormalizedAlert(
                            alert_id=record.alert_id,
                            investigation_id=record.investigation_id,
                            correlation_id=record.correlation_id,
                            source_system=source_enum,
                            source_name=record.source_name or "Unknown",
                            alert_name=record.alert_name,
                            alert_description=record.alert_name,
                            alert_category=record.alert_category or "unknown",
                            severity=sev_enum,
                            confidence=record.confidence or 0.8,
                            primary_entities=record.primary_entities or {},
                            raw_alert=record.alert_metadata or {},
                            timestamp_generated=record.timestamp_generated.isoformat() if hasattr(record.timestamp_generated, "isoformat") else str(record.timestamp_generated),
                            timestamp_received=record.timestamp_received.isoformat() if hasattr(record.timestamp_received, "isoformat") else str(record.timestamp_received)
                        )
                        alerts.append(alert)
                        record.status = "in_progress"
                    
                    if records:
                        db.commit()
                    return alerts
        except Exception:
            pass
        
        # Fallback to in-memory alerts
        pending = list(self.in_memory_alerts)
        self.in_memory_alerts.clear()
        return pending
    
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
