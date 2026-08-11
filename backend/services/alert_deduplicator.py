"""Alert deduplication service."""

import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from backend.models.alert import (
    NormalizedAlert,
    AlertDeduplicationResult,
)


class AlertDeduplicator:
    """Deduplicates alerts within configurable time window."""
    
    def __init__(self, window_seconds: int = 1800):
        """
        Initialize deduplicator.
        
        Args:
            window_seconds: Time window for deduplication (default 30 minutes)
        """
        self.window_seconds = window_seconds
        self.recent_alerts: Dict[str, NormalizedAlert] = {}
        self.alert_fingerprints: Dict[str, str] = {}  # fingerprint -> alert_id
    
    def deduplicate(self, alert: NormalizedAlert) -> AlertDeduplicationResult:
        """
        Check if alert is duplicate, return result with merged data.
        
        Returns:
            AlertDeduplicationResult with:
            - is_duplicate: Whether this is a duplicate
            - normalized_alert: The alert to process (merged if duplicate)
            - parent_alert_id: If duplicate, ID of the original alert
            - occurrence_count: Total occurrences including this one
        """
        fingerprint = self._create_fingerprint(alert)
        
        if fingerprint in self.alert_fingerprints:
            # This is a duplicate
            parent_alert_id = self.alert_fingerprints[fingerprint]
            parent_alert = self.recent_alerts[parent_alert_id]
            
            # Update parent alert with duplicate info
            parent_alert.occurrence_count += 1
            parent_alert.last_occurrence = alert.timestamp_received
            parent_alert.deduplicated_alert_ids.append(alert.alert_id)
            
            # Merge severity (take highest)
            severity_order = ['informational', 'low', 'medium', 'high', 'critical']
            if severity_order.index(alert.severity.value) > severity_order.index(parent_alert.severity.value):
                parent_alert.severity = alert.severity
            
            # Merge primary entities
            for entity_type, entity_data in alert.primary_entities.items():
                if entity_type not in parent_alert.primary_entities and entity_data:
                    parent_alert.primary_entities[entity_type] = entity_data
            
            return AlertDeduplicationResult(
                is_duplicate=True,
                normalized_alert=parent_alert,
                parent_alert_id=parent_alert_id,
                occurrence_count=parent_alert.occurrence_count
            )
        else:
            # New alert
            self.alert_fingerprints[fingerprint] = alert.alert_id
            self.recent_alerts[alert.alert_id] = alert
            
            return AlertDeduplicationResult(
                is_duplicate=False,
                normalized_alert=alert,
                occurrence_count=1
            )
    
    def cleanup_expired(self) -> int:
        """
        Remove alerts outside the deduplication window.
        
        Returns:
            Number of alerts cleaned up
        """
        current_time = datetime.utcnow()
        window_delta = timedelta(seconds=self.window_seconds)
        
        expired_alert_ids = []
        
        for alert_id, alert in self.recent_alerts.items():
            alert_time = datetime.fromisoformat(
                alert.timestamp_received.replace('Z', '+00:00')
            )
            
            if current_time - alert_time > window_delta:
                expired_alert_ids.append(alert_id)
        
        # Clean up
        for alert_id in expired_alert_ids:
            del self.recent_alerts[alert_id]
            
            # Find and remove fingerprint
            fingerprint = None
            for fp, aid in self.alert_fingerprints.items():
                if aid == alert_id:
                    fingerprint = fp
                    break
            
            if fingerprint:
                del self.alert_fingerprints[fingerprint]
        
        return len(expired_alert_ids)
    
    def _create_fingerprint(self, alert: NormalizedAlert) -> str:
        """
        Create fingerprint for deduplication.
        
        Uses key alert characteristics to identify duplicates.
        Fingerprint is based on:
        - Alert name
        - Source system
        - Primary entities (user, host, IP)
        - Category
        """
        key_fields = [
            alert.source_name,
            alert.alert_name,
            alert.alert_category,
            str(alert.primary_entities.get('user', {}).get('name', '')),
            str(alert.primary_entities.get('user', {}).get('id', '')),
            str(alert.primary_entities.get('host', {}).get('hostname', '')),
            str(alert.primary_entities.get('host', {}).get('id', '')),
            str(alert.primary_entities.get('ip', '')),
            str(alert.primary_entities.get('remote_ip', '')),
        ]
        
        fingerprint_str = '|'.join(key_fields)
        return hashlib.md5(fingerprint_str.encode()).hexdigest()
    
    def get_alert_count(self) -> int:
        """Get current count of tracked alerts."""
        return len(self.recent_alerts)
    
    def clear(self):
        """Clear all tracked alerts."""
        self.recent_alerts.clear()
        self.alert_fingerprints.clear()
