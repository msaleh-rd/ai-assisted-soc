"""Neo4j graph database integration."""

from typing import Optional, List, Dict, Any
try:
    from neo4j import AsyncDriver, AsyncSession
except ImportError:
    AsyncDriver = None
    AsyncSession = None


class Neo4jClient:
    """Neo4j graph database client."""
    
    def __init__(self, uri: str, user: str, password: str):
        """
        Initialize Neo4j client.
        
        Args:
            uri: Neo4j connection URI (e.g., "bolt://localhost:7687")
            user: Neo4j username
            password: Neo4j password
        """
        from neo4j import AsyncGraphDatabase
        self.driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    
    async def close(self):
        """Close connection."""
        await self.driver.close()
    
    async def create_entity_node(self, entity_id: str, entity_type: str,
                                attributes: Dict[str, Any]) -> bool:
        """Create entity node in graph."""
        query = """
        CREATE (e:Entity {
            entity_id: $entity_id,
            entity_type: $entity_type,
            attributes: $attributes,
            created_at: datetime()
        })
        """
        
        async with self.driver.session() as session:
            await session.run(query, {
                'entity_id': entity_id,
                'entity_type': entity_type,
                'attributes': attributes
            })
        
        return True
    
    async def create_relationship(self, source_id: str, target_id: str,
                                 relationship_type: str,
                                 properties: Dict[str, Any]) -> bool:
        """Create relationship between entities."""
        query = """
        MATCH (source:Entity {entity_id: $source_id})
        MATCH (target:Entity {entity_id: $target_id})
        CREATE (source)-[r:RELATED {
            type: $relationship_type,
            properties: $properties,
            created_at: datetime()
        }]->(target)
        """
        
        async with self.driver.session() as session:
            await session.run(query, {
                'source_id': source_id,
                'target_id': target_id,
                'relationship_type': relationship_type,
                'properties': properties
            })
        
        return True
    
    async def find_attack_paths(self, source_entity_id: str,
                               target_entity_id: str,
                               max_depth: int = 3) -> List[List[Dict]]:
        """
        Find attack paths between two entities.
        
        Returns:
            List of paths, each path is a list of nodes/relationships
        """
        query = """
        MATCH paths = shortestPath(
            (source:Entity {entity_id: $source_id})-[*..{max_depth}]->
            (target:Entity {entity_id: $target_id})
        )
        RETURN paths
        """
        
        async with self.driver.session() as session:
            result = await session.run(query, {
                'source_id': source_entity_id,
                'target_id': target_entity_id,
                'max_depth': max_depth
            })
            
            records = await result.all()
            return [record['paths'] for record in records]
    
    async def get_entity_neighborhood(self, entity_id: str,
                                     depth: int = 1) -> Dict[str, Any]:
        """
        Get all entities and relationships within N hops.
        
        Returns:
            Dict with nodes and relationships
        """
        query = """
        MATCH (center:Entity {entity_id: $entity_id})
        MATCH (center)-[r*..{depth}]-(neighbors:Entity)
        RETURN center, collect(neighbors) as neighbors, collect(r) as relationships
        """
        
        async with self.driver.session() as session:
            result = await session.run(query, {
                'entity_id': entity_id,
                'depth': depth
            })
            
            records = await result.all()
            if records:
                return {
                    'center': dict(records[0]['center']),
                    'neighbors': [dict(n) for n in records[0]['neighbors']],
                    'relationships': records[0]['relationships']
                }
        
        return {'center': None, 'neighbors': [], 'relationships': []}


def create_neo4j_indexes(driver: AsyncDriver):
    """Create recommended indexes on Neo4j."""
    indexes = [
        "CREATE INDEX entity_id IF NOT EXISTS FOR (e:Entity) ON (e.entity_id)",
        "CREATE INDEX entity_type IF NOT EXISTS FOR (e:Entity) ON (e.entity_type)",
        "CREATE INDEX relationship_type IF NOT EXISTS FOR ()-[r:RELATED]-() ON (r.type)",
    ]
    
    async def run_indexes():
        async with driver.session() as session:
            for index_query in indexes:
                await session.run(index_query)
    
    return run_indexes()
