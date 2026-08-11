"""Alert data models for the AI-Native SOC Platform."""

from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4


class AlertSeverity(str, Enum):
    """Standard alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertSource(str, Enum):
    """Supported alert sources."""
    SIEM = "siem"
    XDR = "xdr"
    EDR = "edr"
    CLOUD = "cloud"
    IAM = "iam"
    OTHER = "other"


class AlertStatus(str, Enum):
    """Alert lifecycle states."""
    RECEIVED = "received"
    DEDUPLICATED = "deduplicated"
    NORMALIZED = "normalized"
    ENRICHED = "enriched"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


@dataclass
class Entity:
    """Represents an entity (user, host, process, IP, domain, file) from alert."""
    entity_type: str  # 'user', 'host', 'process', 'ip', 'domain', 'file'
    entity_id: str
    entity_name: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None

    def __hash__(self):
        return hash((self.entity_type, self.entity_id))


@dataclass
class NormalizedAlert:
    """Standard normalized alert format from any security source."""
    
    # Identifiers
    alert_id: str
    correlation_id: str
    investigation_id: str
    
    # Temporal info
    timestamp_generated: str  # ISO 8601 format
    timestamp_received: str  # ISO 8601 format
    
    # Source information
    source_system: AlertSource
    source_name: str  # e.g., 'CrowdStrike', 'Splunk', 'Cortex XDR'
    
    # Alert details
    alert_name: str
    alert_description: str
    alert_category: str  # MITRE ATT&CK tactic or custom category
    severity: AlertSeverity
    confidence: float  # 0.0-1.0
    
    # Context - non-default fields
    primary_entities: Dict[str, Any]  # User, host, process, IP, etc.
    raw_alert: Dict[str, Any]  # Original raw alert for audit trail
    
    # Status and metadata - default fields
    status: AlertStatus = AlertStatus.NORMALIZED
    alert_metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Deduplication tracking
    occurrence_count: int = 1
    last_occurrence: Optional[str] = None
    deduplicated_alert_ids: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        pass  # Initialization already handled via field defaults

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['source_system'] = self.source_system.value
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NormalizedAlert':
        """Create from dictionary."""
        data_copy = data.copy()
        data_copy['source_system'] = AlertSource(data_copy['source_system'])
        data_copy['severity'] = AlertSeverity(data_copy['severity'])
        data_copy['status'] = AlertStatus(data_copy.get('status', 'normalized'))
        return cls(**data_copy)


@dataclass
class AlertDeduplicationResult:
    """Result of deduplication operation."""
    is_duplicate: bool
    normalized_alert: NormalizedAlert
    parent_alert_id: Optional[str] = None  # If duplicate, which alert it duped
    occurrence_count: int = 1


@dataclass
class AlertNormalizationResult:
    """Result of alert normalization."""
    success: bool
    normalized_alert: Optional[NormalizedAlert] = None
    error: Optional[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
