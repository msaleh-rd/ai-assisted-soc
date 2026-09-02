"""Security Knowledge Graph at Ingest — Wave 3 / Phase M (narrowly scoped).

Writes entity nodes/edges to Neo4j *as alerts and evidence arrive*, rather
than only when an investigation actively queries them, per the plan's Step 1.

Scoping note (documented, not silently skipped): this phase is explicitly
flagged in the implementation plan as the single highest-effort item in the
entire roadmap ("Very High effort... consider deferring... genuine
architecture shift"), with an explicit suggestion to scope the first version
narrowly to just user->host->process relationships. That narrow scope is
exactly what this module implements:

    user --LOGGED_IN_TO--> host --CONTAINS--> process

Wiring this into `rca_engine.py`'s blast-radius computation (currently a
synchronous `len(investigation_package.impacted_assets)` log-derived count)
was evaluated and deliberately NOT done in this pass: `rca_engine.py`'s core
analysis call chain is fully synchronous, while Neo4j access in this codebase
is fully async (`Neo4jClient` uses `neo4j.AsyncGraphDatabase`) -- bridging
that would require a broader async-ification of `rca_engine.py` well beyond
this phase's narrowed scope, and risks the exact kind of regression the plan
warns about. Instead, the new `Neo4jClient.get_blast_radius()` traversal (see
`backend/database/neo4j.py`) is wired into the Response phase instead
(`response_orchestration.py`, which is already fully async), giving
analysts/automation real graph-derived blast-radius visibility before
executing a containment action, without touching the synchronous RCA engine.
"""

import logging
from typing import Optional

logger = logging.getLogger("graph_ingest")


async def record_user_host_process(
    user_id: Optional[str] = None,
    host_id: Optional[str] = None,
    process_id: Optional[str] = None,
    process_name: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> bool:
    """Best-effort, ingest-time graph materialization of the narrow
    user->host->process relationship set. Never raises -- mirrors the
    DB-optional pattern used throughout this codebase (investigation_ledger,
    entity_risk, compounding_memory): if Neo4j isn't configured/reachable,
    this is a silent no-op rather than blocking the investigation pipeline.

    Returns True if at least one node/relationship write was attempted and
    did not raise, False otherwise (nothing to write, or Neo4j unavailable).
    """
    try:
        from backend.database.connection import get_neo4j
    except Exception as e:
        logger.debug(f"Graph ingest skipped (import): {e}")
        return False

    neo4j = get_neo4j()
    if neo4j is None:
        return False

    try:
        wrote_anything = False

        if host_id:
            await neo4j.create_entity_node(entity_id=host_id, entity_type="host", attributes={})
            wrote_anything = True
        if user_id:
            await neo4j.create_entity_node(entity_id=user_id, entity_type="user", attributes={})
            wrote_anything = True
        if process_id:
            await neo4j.create_entity_node(
                entity_id=str(process_id),
                entity_type="process",
                attributes={"process_name": process_name} if process_name else {},
            )
            wrote_anything = True

        if user_id and host_id:
            await neo4j.create_relationship(
                source_id=user_id,
                target_id=host_id,
                relationship_type="logged_in_to",
                properties={"timestamp": timestamp} if timestamp else {},
            )
        if host_id and process_id:
            await neo4j.create_relationship(
                source_id=host_id,
                target_id=str(process_id),
                relationship_type="contains",
                properties={"timestamp": timestamp} if timestamp else {},
            )

        return wrote_anything
    except Exception as e:
        logger.debug(f"Graph ingest skipped (write): {e}")
        return False
