"""Evidence collection orchestration and entity expansion."""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from uuid import uuid4

from backend.models.alert import NormalizedAlert
from backend.models.entities import (
    EntityNode,
    EntityType,
    EntityRelationship,
    RelationshipType,
    EntityFactory,
)


class EvidenceCollector(ABC):
    """Base class for evidence collectors targeting specific entity types."""
    
    def __init__(self, entity_type: EntityType):
        self.entity_type = entity_type
        self.name = f"{entity_type.value}_collector"
    
    @abstractmethod
    async def collect(self, entity_id: str, 
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect evidence for an entity.
        
        Returns:
            Dict with enrichment_data and relationships
        """
        pass


class UserEvidenceCollector(EvidenceCollector):
    """Collect user-related evidence."""
    
    def __init__(self):
        super().__init__(EntityType.USER)
    
    async def collect(self, user_id: str,
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Collect user profile, activities, and risk indicators."""
        # This would query actual systems (AD, Okta, etc.)
        # For now, simulated data
        return {
            'enrichment_data': {
                'email': f"{user_id}@company.com",
                'department': 'Engineering',
                'title': 'Software Engineer',
                'manager': 'manager@company.com',
                'mfa_enabled': True,
                'account_enabled': True,
                'last_login': datetime.utcnow().isoformat() + 'Z',
                'failed_login_count': 0,
                'privileged': False,
                'groups': ['Engineering', 'Development'],
            },
            'threat_intel': {
                'credentials_exposed': False,
                'high_risk_login': False,
                'unusual_location': False,
            },
            'risk_score': 0.1,
        }


class HostEvidenceCollector(EvidenceCollector):
    """Collect host-related evidence."""
    
    def __init__(self):
        super().__init__(EntityType.HOST)
    
    async def collect(self, host_id: str,
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Collect host configuration, processes, and security posture."""
        return {
            'enrichment_data': {
                'os': 'Windows 10',
                'os_version': '21H2',
                'domain': 'company.local',
                'is_server': False,
                'endpoint_protection': 'CrowdStrike Falcon',
                'last_seen': datetime.utcnow().isoformat() + 'Z',
                'security_posture': 'patched',
                'running_processes': 147,
                'disk_usage': '73%',
                'memory_usage': '42%',
            },
            'threat_intel': {
                'last_malware_detection': None,
                'vulnerability_count': 0,
                'failed_patches': 0,
            },
            'risk_score': 0.15,
        }


class ProcessEvidenceCollector(EvidenceCollector):
    """Collect process-related evidence."""
    
    def __init__(self):
        super().__init__(EntityType.PROCESS)
    
    async def collect(self, process_id: str,
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Collect process details, parents, and behavior."""
        return {
            'enrichment_data': {
                'signature_status': 'signed',
                'signer': 'Microsoft Corporation',
                'start_time': datetime.utcnow().isoformat() + 'Z',
                'network_connections': 0,
                'file_handles': 23,
                'loaded_dlls': 42,
            },
            'threat_intel': {
                'known_malware': False,
                'unsigned': False,
                'suspicious_imports': False,
                'api_hooks': False,
            },
            'risk_score': 0.05,
        }


class IPAddressEvidenceCollector(EvidenceCollector):
    """Collect IP address-related evidence."""
    
    def __init__(self):
        super().__init__(EntityType.IP_ADDRESS)
    
    async def collect(self, ip_address: str,
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Collect IP geolocation, reputation, and threat data."""
        return {
            'enrichment_data': {
                'geolocation': 'San Francisco, USA',
                'asn': 'AS15169 (Google)',
                'isp': 'Google Cloud',
                'observed_ports': [443, 80],
                'observed_protocols': ['https', 'http', 'dns'],
            },
            'threat_intel': {
                'reputation': 'clean',
                'known_threats': [],
                'in_blocklist': False,
                'phishing_attempts': 0,
                'malware_c2': False,
            },
            'risk_score': 0.0,
        }


class DomainEvidenceCollector(EvidenceCollector):
    """Collect domain-related evidence."""
    
    def __init__(self):
        super().__init__(EntityType.DOMAIN)
    
    async def collect(self, domain: str,
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Collect domain registration, DNS, and threat data."""
        return {
            'enrichment_data': {
                'registrar': 'GoDaddy',
                'registration_date': '2015-03-15',
                'expiration_date': '2025-03-15',
                'dns_records': {
                    'A': ['93.184.216.34'],
                    'MX': ['mail.example.com'],
                    'TXT': ['v=spf1 include:_spf.google.com ~all'],
                },
            },
            'threat_intel': {
                'reputation': 'clean',
                'known_threats': [],
                'typosquatting': False,
                'phishing_domain': False,
                'malware_c2': False,
            },
            'risk_score': 0.0,
        }


class FileEvidenceCollector(EvidenceCollector):
    """Collect file-related evidence."""
    
    def __init__(self):
        super().__init__(EntityType.FILE)
    
    async def collect(self, file_path: str,
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Collect file metadata, hashes, and reputation."""
        return {
            'enrichment_data': {
                'size_bytes': 524288,
                'created_time': '2023-01-15T10:30:00Z',
                'modified_time': '2024-08-10T14:22:00Z',
                'owner': 'SYSTEM',
                'mime_type': 'application/x-msdownload',
            },
            'threat_intel': {
                'reputation': 'clean',
                'known_malware': False,
                'signed': True,
                'signer': 'Microsoft Corporation',
                'detection_ratio': '0/72',
            },
            'risk_score': 0.0,
        }


class EvidenceCollectorRegistry:
    """Registry of evidence collectors for different entity types."""
    
    def __init__(self):
        self.collectors: Dict[EntityType, EvidenceCollector] = {
            EntityType.USER: UserEvidenceCollector(),
            EntityType.HOST: HostEvidenceCollector(),
            EntityType.PROCESS: ProcessEvidenceCollector(),
            EntityType.IP_ADDRESS: IPAddressEvidenceCollector(),
            EntityType.DOMAIN: DomainEvidenceCollector(),
            EntityType.FILE: FileEvidenceCollector(),
        }
    
    def get_collector(self, entity_type: EntityType) -> Optional[EvidenceCollector]:
        """Get collector for entity type."""
        return self.collectors.get(entity_type)
    
    def register_collector(self, entity_type: EntityType, 
                          collector: EvidenceCollector):
        """Register a custom collector."""
        self.collectors[entity_type] = collector


class EvidenceCollectionOrchestrator:
    """Orchestrates parallel evidence collection for investigation entities."""
    
    def __init__(self):
        self.registry = EvidenceCollectorRegistry()
        self.max_parallel_tasks = 10
    
    async def collect_for_alert(self, alert: NormalizedAlert,
                               max_depth: int = 2) -> Dict[str, Any]:
        """
        Collect evidence for all entities in alert.
        
        Args:
            alert: The normalized alert
            max_depth: Maximum entity expansion depth
        
        Returns:
            Investigation context with entities, relationships, and enrichment
        """
        investigation_id = alert.investigation_id
        
        # Initialize context
        context = {
            'investigation_id': investigation_id,
            'alert_id': alert.alert_id,
            'correlation_id': alert.correlation_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'entities': {},  # entity_id -> EntityNode
            'relationships': [],  # List of EntityRelationship
            'enrichment_data': {},  # entity_id -> enrichment dict
        }
        
        # Extract initial entities from alert
        initial_entities = self._extract_entities_from_alert(alert)
        
        # Collect evidence for each entity
        await self._collect_evidence_recursive(
            initial_entities,
            context,
            depth=0,
            max_depth=max_depth
        )
        
        return context
    
    def _extract_entities_from_alert(self, alert: NormalizedAlert) -> List[EntityNode]:
        """Extract entities from alert's primary_entities."""
        entities = []
        
        # User entity
        if alert.primary_entities.get('user'):
            user_data = alert.primary_entities['user']
            user_id = user_data.get('id') or user_data.get('name', 'unknown')
            user_name = user_data.get('name', user_id)
            
            entity = EntityFactory.create_user_entity(user_id, user_name, user_data)
            entity.source_alerts = [alert.alert_id]
            entity.confidence = alert.confidence
            entities.append(entity)
        
        # Host entity
        if alert.primary_entities.get('host'):
            host_data = alert.primary_entities['host']
            host_id = host_data.get('id') or host_data.get('hostname', 'unknown')
            hostname = host_data.get('hostname', host_id)
            
            entity = EntityFactory.create_host_entity(host_id, hostname, host_data)
            entity.source_alerts = [alert.alert_id]
            entity.confidence = alert.confidence
            entities.append(entity)
        
        # IP entity
        if alert.primary_entities.get('ip'):
            ip_addr = alert.primary_entities['ip']
            if ip_addr:
                entity = EntityFactory.create_ip_entity(ip_addr, {})
                entity.source_alerts = [alert.alert_id]
                entity.confidence = alert.confidence
                entities.append(entity)
        
        # Remote IP entity
        if alert.primary_entities.get('remote_ip'):
            remote_ip = alert.primary_entities['remote_ip']
            if remote_ip:
                entity = EntityFactory.create_ip_entity(remote_ip, {})
                entity.source_alerts = [alert.alert_id]
                entity.confidence = alert.confidence
                entities.append(entity)
        
        return entities
    
    async def _collect_evidence_recursive(self, entities: List[EntityNode],
                                         context: Dict[str, Any],
                                         depth: int, max_depth: int):
        """Recursively collect evidence with depth limit."""
        if depth > max_depth:
            return
        
        # Add entities to context
        for entity in entities:
            if entity.entity_id not in context['entities']:
                context['entities'][entity.entity_id] = entity
        
        # Collect evidence for each entity
        collection_tasks = []
        for entity in entities:
            collector = self.registry.get_collector(entity.entity_type)
            if collector:
                collection_tasks.append(
                    self._collect_and_enrich(entity, collector, context)
                )
        
        # Run collections in parallel with semaphore
        if collection_tasks:
            semaphore = asyncio.Semaphore(self.max_parallel_tasks)
            
            async def bounded_collect(task):
                async with semaphore:
                    return await task
            
            await asyncio.gather(*[bounded_collect(task) for task in collection_tasks])
    
    async def _collect_and_enrich(self, entity: EntityNode,
                                 collector: EvidenceCollector,
                                 context: Dict[str, Any]):
        """Collect evidence and enrich entity."""
        try:
            evidence = await collector.collect(entity.entity_id, context)
            
            # Update entity enrichment
            entity.enrichment_data.update(evidence.get('enrichment_data', {}))
            entity.threat_intel.update(evidence.get('threat_intel', {}))
            entity.risk_score = evidence.get('risk_score', 0.0)
            
            # Store enrichment data
            context['enrichment_data'][entity.entity_id] = evidence
            
        except Exception as e:
            # Log error but continue
            print(f"Error collecting evidence for {entity.entity_id}: {e}")


def get_evidence_orchestrator() -> EvidenceCollectionOrchestrator:
    """Get evidence collection orchestrator singleton."""
    # Could be cached globally
    return EvidenceCollectionOrchestrator()
