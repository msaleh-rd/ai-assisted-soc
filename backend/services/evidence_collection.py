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
from backend.database.connection import SessionLocal
from backend.database.postgres import EntityRecord, EventRecord
import logging

logger = logging.getLogger(__name__)


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

    def _fetch_from_db(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Fetch real evidence from the Postgres database."""
        if not SessionLocal:
            return None
            
        db = SessionLocal()
        try:
            record = db.query(EntityRecord).filter_by(entity_id=entity_id).first()
            if record:
                return {
                    'enrichment_data': record.enrichment_data or {},
                    'threat_intel': record.threat_intel or {},
                    'risk_score': record.risk_score or 0.0,
                    'is_known_malicious': record.is_known_malicious or False,
                    'is_suspicious': record.is_suspicious or False,
                }
            return None
        except Exception as e:
            logger.error(f"Error fetching entity {entity_id} from DB: {e}")
            return None
        finally:
            db.close()

    @staticmethod
    def _get_ingestor():
        """Lazy import of LogIngestor to avoid circular dependencies."""
        try:
            from backend.services.evidence.log_ingestor import get_log_ingestor
            return get_log_ingestor()
        except Exception as e:
            logger.warning(f"Could not initialize LogIngestor: {e}")
            return None

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if an IPv4 address is in a private/RFC1918 range or loopback."""
        ip_str = ip_str.strip()
        if ip_str in ("127.0.0.1", "localhost", "::1"):
            return True
        parts = ip_str.split(".")
        if len(parts) == 4:
            try:
                p0, p1 = int(parts[0]), int(parts[1])
                if p0 == 10:
                    return True
                if p0 == 172 and 16 <= p1 <= 31:
                    return True
                if p0 == 192 and p1 == 168:
                    return True
                if p0 == 169 and p1 == 254:
                    return True
            except ValueError:
                pass
        return False


from backend.services.evidence.skill_handlers import EvidenceSkillExecutor


class UserEvidenceCollector(EvidenceCollector):
    """Collect user-related evidence via identity-ad-lookup skill."""
    
    def __init__(self):
        super().__init__(EntityType.USER)
    
    async def collect(self, user_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return await EvidenceSkillExecutor.execute_skill("identity-ad-lookup", user_id, "user", context)


class HostEvidenceCollector(EvidenceCollector):
    """Collect host-related evidence via persistence-auditor and telemetry."""
    
    def __init__(self):
        super().__init__(EntityType.HOST)
    
    async def collect(self, host_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return await EvidenceSkillExecutor.execute_skill("persistence-auditor", host_id, "host", context)


class ProcessEvidenceCollector(EvidenceCollector):
    """Collect process-related evidence via edr-process-tree skill."""
    
    def __init__(self):
        super().__init__(EntityType.PROCESS)
    
    async def collect(self, process_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return await EvidenceSkillExecutor.execute_skill("edr-process-tree", process_id, "process", context)


class IPAddressEvidenceCollector(EvidenceCollector):
    """Collect IP address-related evidence via network-flow-analyzer skill."""
    
    def __init__(self):
        super().__init__(EntityType.IP_ADDRESS)
    
    async def collect(self, ip_address: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return await EvidenceSkillExecutor.execute_skill("network-flow-analyzer", ip_address, "ip", context)


class DomainEvidenceCollector(EvidenceCollector):
    """Collect domain-related evidence via threat-intel-lookup skill."""
    
    def __init__(self):
        super().__init__(EntityType.DOMAIN)
    
    async def collect(self, domain: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return await EvidenceSkillExecutor.execute_skill("threat-intel-lookup", domain, "domain", context)


class FileEvidenceCollector(EvidenceCollector):
    """Collect file-related evidence via file-forensics skill."""
    
    def __init__(self):
        super().__init__(EntityType.FILE)
    
    async def collect(self, file_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return await EvidenceSkillExecutor.execute_skill("file-forensics", file_path, "file", context)



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
    
    async def collect_for_entities(self, entities_data: List[Dict[str, Any]],
                                  investigation_id: str = "unknown",
                                  max_depth: int = 2) -> Dict[str, Any]:
        """
        Collect evidence for a list of raw entity dictionaries.
        
        Args:
            entities_data: List of dicts with 'type', 'id', and other attributes
            investigation_id: The investigation ID
            max_depth: Maximum entity expansion depth
            
        Returns:
            Investigation context with entities, relationships, and enrichment
        """
        context = {
            'investigation_id': investigation_id,
            'alert_id': 'unknown',
            'correlation_id': 'unknown',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'entities': {},  # entity_id -> EntityNode
            'relationships': [],  # List of EntityRelationship
            'enrichment_data': {},  # entity_id -> enrichment dict
        }
        
        initial_entities = []
        type_mapping = {
            "ip": EntityType.IP_ADDRESS,
            "ip_address": EntityType.IP_ADDRESS,
            "host": EntityType.HOST,
            "hostname": EntityType.HOST,
            "endpoint": EntityType.HOST,
            "user": EntityType.USER,
            "username": EntityType.USER,
            "account": EntityType.USER,
            "file": EntityType.FILE,
            "filepath": EntityType.FILE,
            "filename": EntityType.FILE,
            "process": EntityType.PROCESS,
            "process_name": EntityType.PROCESS,
            "domain": EntityType.DOMAIN,
            "url": EntityType.DOMAIN,
        }
        for ent_data in entities_data:
            ent_type_str = str(ent_data.get('type', 'unknown')).lower()
            ent_id = ent_data.get('id', 'unknown')
            ent_name = ent_data.get('name', ent_id)
            
            ent_type = type_mapping.get(ent_type_str)
            if not ent_type:
                try:
                    ent_type = EntityType(ent_type_str)
                except ValueError:
                    continue
                
            if ent_type == EntityType.USER:
                entity = EntityFactory.create_user_entity(ent_id, ent_name, ent_data)
            elif ent_type == EntityType.HOST:
                entity = EntityFactory.create_host_entity(ent_id, ent_name, ent_data)
            elif ent_type == EntityType.IP_ADDRESS:
                entity = EntityFactory.create_ip_entity(ent_id, ent_data)
            else:
                entity = EntityNode(
                    entity_id=ent_id,
                    entity_type=ent_type,
                    entity_name=ent_name,
                    attributes=ent_data
                )
            initial_entities.append(entity)
            
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
