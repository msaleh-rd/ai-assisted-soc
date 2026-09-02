"""Entity data models for graph representation."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class EntityType(str, Enum):
    """Supported entity types for investigation."""
    USER = "user"
    HOST = "host"
    PROCESS = "process"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE = "file"
    NETWORK_FLOW = "network_flow"
    APPLICATION = "application"


class RelationshipType(str, Enum):
    """Types of relationships between entities."""
    # User relationships
    LOGGED_IN_TO = "logged_in_to"
    EXECUTED = "executed"
    ACCESSED = "accessed"
    MODIFIED = "modified"
    CREATED = "created"
    DELETED = "deleted"
    RECEIVED = "received"  # email received
    SENT = "sent"  # email sent
    OWNS = "owns"
    MEMBER_OF = "member_of"
    
    # Host relationships
    CONTAINS = "contains"  # host contains process
    INITIATED = "initiated"  # host initiated connection
    CONNECTED_TO = "connected_to"
    RESOLVED_TO = "resolved_to"  # domain resolved to IP
    
    # Process relationships
    SPAWNED = "spawned"  # process spawned another
    CHILD_OF = "child_of"
    PARENT_OF = "parent_of"
    LOADED = "loaded"  # loaded DLL
    INJECTED_INTO = "injected_into"
    
    # File relationships
    WROTE_TO = "wrote_to"
    READ_FROM = "read_from"
    EXECUTED_FROM = "executed_from"
    
    # Attack relationships
    INDICATOR_OF = "indicator_of"  # File is indicator of attack
    ASSOCIATED_WITH = "associated_with"  # Event associated with attack


@dataclass
class EntityNode:
    """Represents an entity node in the investigation graph."""
    
    entity_id: str  # Unique identifier
    entity_type: EntityType
    entity_name: str
    
    # Attributes specific to entity type
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    # Enrichment data
    enrichment_data: Dict[str, Any] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen_at: Optional[str] = None
    confidence: float = 0.85
    risk_score: float = 0.0
    
    # Tracking
    source_alerts: List[str] = field(default_factory=list)  # Alert IDs that led to this
    is_suspicious: bool = False
    is_known_malicious: bool = False
    
    def __hash__(self):
        return hash((self.entity_type.value, self.entity_id))
    
    def __eq__(self, other):
        if not isinstance(other, EntityNode):
            return False
        return self.entity_type == other.entity_type and self.entity_id == other.entity_id


@dataclass
class EntityRelationship:
    """Represents a directed edge between two entities."""
    
    source_entity_id: str
    source_entity_type: EntityType
    
    target_entity_id: str
    target_entity_type: EntityType
    
    relationship_type: RelationshipType
    
    # Context
    timestamp: str  # ISO 8601 when relationship was observed
    context: Dict[str, Any] = field(default_factory=dict)  # Additional context
    
    # Confidence and risk
    confidence: float = 0.85
    risk_score: float = 0.0
    
    # Metadata
    source_alerts: List[str] = field(default_factory=list)  # Alert IDs that revealed this
    is_suspicious: bool = False
    
    def __hash__(self):
        return hash((
            self.source_entity_id,
            self.target_entity_id,
            self.relationship_type.value
        ))


@dataclass
class UserEntity:
    """User-specific attributes."""
    user_id: str
    username: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    manager: Optional[str] = None
    mfa_enabled: bool = False
    account_enabled: bool = True
    last_login: Optional[str] = None
    failed_login_count: int = 0
    password_age_days: Optional[int] = None
    privileged: bool = False
    groups: List[str] = field(default_factory=list)


@dataclass
class HostEntity:
    """Host-specific attributes."""
    host_id: str
    hostname: str
    fqdn: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    domain: Optional[str] = None
    is_server: bool = False
    endpoint_protection: Optional[str] = None
    last_seen: Optional[str] = None
    security_posture: Optional[str] = None  # 'patched', 'vulnerable', 'unknown'


@dataclass
class ProcessEntity:
    """Process-specific attributes."""
    process_id: int
    process_name: str
    process_path: str
    command_line: str
    user: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    signature_status: Optional[str] = None  # 'signed', 'unsigned', 'invalid'
    signer: Optional[str] = None


@dataclass
class IPAddressEntity:
    """IP address-specific attributes."""
    ip_address: str
    version: int = 4  # 4 or 6
    geolocation: Optional[str] = None
    asn: Optional[str] = None
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    reputation: Optional[str] = None  # 'malicious', 'suspicious', 'clean'
    observed_ports: List[int] = field(default_factory=list)
    observed_protocols: List[str] = field(default_factory=list)


@dataclass
class DomainEntity:
    """Domain-specific attributes."""
    domain: str
    fqdn: Optional[str] = None
    registrar: Optional[str] = None
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    registrant: Optional[str] = None
    dns_records: Dict[str, List[str]] = field(default_factory=dict)  # Type -> records
    reputation: Optional[str] = None  # 'malicious', 'suspicious', 'clean'
    threat_intel: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileEntity:
    """File-specific attributes."""
    file_path: str
    filename: str
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    created_time: Optional[str] = None
    modified_time: Optional[str] = None
    accessed_time: Optional[str] = None
    owner: Optional[str] = None
    mime_type: Optional[str] = None
    signature_status: Optional[str] = None  # 'signed', 'unsigned', 'invalid'
    signer: Optional[str] = None
    reputation: Optional[str] = None  # 'malicious', 'suspicious', 'clean'


class EntityFactory:
    """Factory for creating entity nodes from specific data."""
    
    @staticmethod
    def create_user_entity(user_id: str, username: str, 
                          attributes: Dict[str, Any]) -> EntityNode:
        """Create user entity node."""
        user_attrs = UserEntity(user_id=user_id, username=username)
        for key, value in attributes.items():
            if hasattr(user_attrs, key):
                setattr(user_attrs, key, value)
        
        return EntityNode(
            entity_id=user_id,
            entity_type=EntityType.USER,
            entity_name=username,
            attributes=user_attrs.__dict__
        )
    
    @staticmethod
    def create_host_entity(host_id: str, hostname: str,
                          attributes: Dict[str, Any]) -> EntityNode:
        """Create host entity node."""
        host_attrs = HostEntity(host_id=host_id, hostname=hostname)
        for key, value in attributes.items():
            if hasattr(host_attrs, key):
                setattr(host_attrs, key, value)
        
        return EntityNode(
            entity_id=host_id,
            entity_type=EntityType.HOST,
            entity_name=hostname,
            attributes=host_attrs.__dict__
        )
    
    @staticmethod
    def create_ip_entity(ip_address: str,
                        attributes: Dict[str, Any]) -> EntityNode:
        """Create IP address entity node."""
        ip_attrs = IPAddressEntity(ip_address=ip_address)
        for key, value in attributes.items():
            if hasattr(ip_attrs, key):
                setattr(ip_attrs, key, value)
        
        return EntityNode(
            entity_id=ip_address,
            entity_type=EntityType.IP_ADDRESS,
            entity_name=ip_address,
            attributes=ip_attrs.__dict__
        )

    @staticmethod
    def create_process_entity(process_id: str, process_name: str,
                             attributes: Dict[str, Any]) -> EntityNode:
        """Create process entity node (Wave 3, Phase M: needed for the
        user->host->process ingest-time graph)."""
        process_attrs = ProcessEntity(
            process_id=int(process_id) if str(process_id).isdigit() else 0,
            process_name=process_name,
            process_path=attributes.get("process_path", ""),
            command_line=attributes.get("command_line", ""),
        )
        for key, value in attributes.items():
            if hasattr(process_attrs, key):
                setattr(process_attrs, key, value)

        return EntityNode(
            entity_id=str(process_id),
            entity_type=EntityType.PROCESS,
            entity_name=process_name,
            attributes=process_attrs.__dict__
        )
