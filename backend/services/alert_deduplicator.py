import copy
import hashlib
from datetime import datetime, timedelta, timezone
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
            for entity_type, entity_data in (alert.primary_entities or {}).items():
                if entity_type not in parent_alert.primary_entities and entity_data:
                    parent_alert.primary_entities[entity_type] = entity_data
            
            return AlertDeduplicationResult(
                is_duplicate=True,
                normalized_alert=parent_alert,
                parent_alert_id=parent_alert_id,
                occurrence_count=parent_alert.occurrence_count
            )
        else:
            # New alert - store a copy so mutations outside don't corrupt state
            stored_alert = copy.deepcopy(alert)
            self.alert_fingerprints[fingerprint] = alert.alert_id
            self.recent_alerts[alert.alert_id] = stored_alert
            
            return AlertDeduplicationResult(
                is_duplicate=False,
                normalized_alert=stored_alert,
                occurrence_count=1
            )
    
    def cleanup_expired(self) -> int:
        """
        Remove alerts outside the deduplication window.
        
        Returns:
            Number of alerts cleaned up
        """
        now_utc = datetime.now(timezone.utc)
        window_delta = timedelta(seconds=self.window_seconds)
        
        expired_alert_ids = []
        
        for alert_id, alert in list(self.recent_alerts.items()):
            ts = alert.timestamp_received
            if isinstance(ts, str):
                alert_time = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            elif isinstance(ts, datetime):
                alert_time = ts
            else:
                alert_time = now_utc
            
            if alert_time.tzinfo is None:
                alert_time = alert_time.replace(tzinfo=timezone.utc)
                
            if (now_utc - alert_time) >= window_delta:
                expired_alert_ids.append(alert_id)
        
        # Clean up
        for alert_id in expired_alert_ids:
            if alert_id in self.recent_alerts:
                del self.recent_alerts[alert_id]
            
            fingerprints_to_del = [fp for fp, aid in self.alert_fingerprints.items() if aid == alert_id]
            for fp in fingerprints_to_del:
                del self.alert_fingerprints[fp]
        
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
        primary_entities = alert.primary_entities or {}
        user_ent = primary_entities.get('user', {})
        host_ent = primary_entities.get('host', {})
        
        user_name = user_ent.get('name', '') if isinstance(user_ent, dict) else str(user_ent)
        user_id = user_ent.get('id', '') if isinstance(user_ent, dict) else ''
        host_name = host_ent.get('hostname', '') if isinstance(host_ent, dict) else str(host_ent)
        host_id = host_ent.get('id', '') if isinstance(host_ent, dict) else ''
        ip_val = primary_entities.get('ip', '')
        remote_ip_val = primary_entities.get('remote_ip', '')

        key_fields = [
            str(alert.source_name),
            str(alert.alert_name),
            str(alert.alert_category),
            str(user_name),
            str(user_id),
            str(host_name),
            str(host_id),
            str(ip_val),
            str(remote_ip_val),
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
