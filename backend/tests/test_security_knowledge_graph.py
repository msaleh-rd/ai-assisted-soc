"""Tests for the Security Knowledge Graph at Ingest (Wave 3, Phase M).

Neo4j has no live server in this dev/test environment, so these tests use a
lightweight fake driver/session that mimics the exact async session/run/
all() interface `Neo4jClient` uses, without needing a real Bolt connection.
"""

from unittest.mock import AsyncMock, patch

import pytest

from backend.database.neo4j import Neo4jClient
from backend.models.entities import EntityFactory, EntityType
from backend.services.graph_ingest import record_user_host_process


class FakeNeo4jResult:
    def __init__(self, records):
        self._records = records

    async def all(self):
        return self._records


class FakeNeo4jSession:
    """Records every query/params pair and returns canned records via a
    query-aware callable, mimicking `async with driver.session() as session`."""

    def __init__(self, records_for_query=None):
        self.executed = []
        self._records_for_query = records_for_query or (lambda query, params: [])

    async def run(self, query, params=None):
        self.executed.append((query, params or {}))
        return FakeNeo4jResult(self._records_for_query(query, params or {}))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _make_client(records_for_query=None) -> Neo4jClient:
    client = Neo4jClient(uri="bolt://localhost:7687", user="neo4j", password="test")
    session = FakeNeo4jSession(records_for_query)
    client.driver.session = lambda: session  # override to bypass real connection
    return client, session


class TestCreateEntityNodeAndRelationship:
    @pytest.mark.asyncio
    async def test_create_entity_node_executes_expected_query(self):
        client, session = _make_client()
        result = await client.create_entity_node(entity_id="HOST-1", entity_type="host", attributes={"os": "windows"})
        assert result is True
        assert len(session.executed) == 1
        query, params = session.executed[0]
        assert "CREATE (e:Entity" in query
        assert params["entity_id"] == "HOST-1"
        assert params["entity_type"] == "host"

    @pytest.mark.asyncio
    async def test_create_relationship_executes_expected_query(self):
        client, session = _make_client()
        result = await client.create_relationship(
            source_id="USER-1", target_id="HOST-1", relationship_type="logged_in_to", properties={}
        )
        assert result is True
        query, params = session.executed[0]
        assert "CREATE (source)-[r:RELATED" in query
        assert params["source_id"] == "USER-1"
        assert params["target_id"] == "HOST-1"
        assert params["relationship_type"] == "logged_in_to"


class TestFindAttackPathsAndNeighborhoodQueryInterpolation:
    """Regression test for the previously-broken (missing f-string prefix)
    variable-length-path queries -- confirms max_depth/depth are now real
    literal integers in the Cypher text, not the literal substring
    '{max_depth}'/'{depth}'."""

    @pytest.mark.asyncio
    async def test_find_attack_paths_interpolates_max_depth(self):
        client, session = _make_client()
        await client.find_attack_paths("A", "B", max_depth=4)
        query, _ = session.executed[0]
        assert "[*..4]->" in query
        assert "{max_depth}" not in query

    @pytest.mark.asyncio
    async def test_get_entity_neighborhood_interpolates_depth(self):
        client, session = _make_client()
        await client.get_entity_neighborhood("A", depth=3)
        query, _ = session.executed[0]
        assert "[r*..3]" in query
        assert "{depth}" not in query


class TestGetNeighbors:
    @pytest.mark.asyncio
    async def test_parses_records_into_dicts(self):
        def records_for_query(query, params):
            assert params["entity_id"] == "user:alice"
            return [
                {"entity_id": "host:WKS-01", "entity_type": "host", "relationship_type": "logged_in_to"},
            ]

        client, _ = _make_client(records_for_query)
        neighbors = await client.get_neighbors("user:alice")
        assert neighbors == [{"entity_id": "host:WKS-01", "entity_type": "host", "relationship_type": "logged_in_to"}]


class TestGetBlastRadius:
    """Plan's exact test spec: ingest a synthetic multi-hop scenario
    (compromised user -> host -> lateral host) and confirm a 2-hop
    blast-radius query returns the correct entity set."""

    @pytest.mark.asyncio
    async def test_two_hop_blast_radius_returns_correct_entity_set(self):
        # user:alice -> host:WKS-01 (hop 1) -> host:DC-01 (hop 2, lateral)
        adjacency = {
            "user:alice": [{"entity_id": "host:WKS-01", "entity_type": "host", "relationship_type": "logged_in_to"}],
            "host:WKS-01": [
                {"entity_id": "user:alice", "entity_type": "user", "relationship_type": "logged_in_to"},
                {"entity_id": "host:DC-01", "entity_type": "host", "relationship_type": "connected_to"},
            ],
            "host:DC-01": [{"entity_id": "host:WKS-01", "entity_type": "host", "relationship_type": "connected_to"}],
        }

        client = Neo4jClient(uri="bolt://localhost:7687", user="neo4j", password="test")

        async def fake_get_neighbors(self_arg, entity_id):
            return adjacency.get(entity_id, [])

        with patch.object(Neo4jClient, "get_neighbors", new=fake_get_neighbors):
            result = await client.get_blast_radius("user:alice", max_hops=2)

        reachable_ids = {e["entity_id"] for e in result["reachable_entities"]}
        assert reachable_ids == {"host:WKS-01", "host:DC-01"}

        hops_by_id = {e["entity_id"]: e["hops"] for e in result["reachable_entities"]}
        assert hops_by_id["host:WKS-01"] == 1
        assert hops_by_id["host:DC-01"] == 2

    @pytest.mark.asyncio
    async def test_one_hop_blast_radius_excludes_lateral_host(self):
        adjacency = {
            "user:alice": [{"entity_id": "host:WKS-01", "entity_type": "host", "relationship_type": "logged_in_to"}],
            "host:WKS-01": [{"entity_id": "host:DC-01", "entity_type": "host", "relationship_type": "connected_to"}],
        }
        client = Neo4jClient(uri="bolt://localhost:7687", user="neo4j", password="test")

        async def fake_get_neighbors(self_arg, entity_id):
            return adjacency.get(entity_id, [])

        with patch.object(Neo4jClient, "get_neighbors", new=fake_get_neighbors):
            result = await client.get_blast_radius("user:alice", max_hops=1)

        reachable_ids = {e["entity_id"] for e in result["reachable_entities"]}
        assert reachable_ids == {"host:WKS-01"}

    @pytest.mark.asyncio
    async def test_isolated_entity_has_empty_blast_radius(self):
        client = Neo4jClient(uri="bolt://localhost:7687", user="neo4j", password="test")

        async def fake_get_neighbors(self_arg, entity_id):
            return []

        with patch.object(Neo4jClient, "get_neighbors", new=fake_get_neighbors):
            result = await client.get_blast_radius("host:ISOLATED", max_hops=2)

        assert result["reachable_entities"] == []


class TestEntityFactoryCreateProcessEntity:
    def test_creates_process_entity_node(self):
        node = EntityFactory.create_process_entity(
            process_id="4242", process_name="powershell.exe",
            attributes={"command_line": "powershell -enc ...", "parent_process_name": "winword.exe"},
        )
        assert node.entity_type == EntityType.PROCESS
        assert node.entity_id == "4242"
        assert node.attributes["command_line"] == "powershell -enc ..."
        assert node.attributes["parent_process_name"] == "winword.exe"


class TestRecordUserHostProcess:
    @pytest.mark.asyncio
    async def test_returns_false_when_neo4j_not_configured(self):
        with patch("backend.database.connection.get_neo4j", return_value=None):
            result = await record_user_host_process(user_id="u1", host_id="h1")
        assert result is False

    @pytest.mark.asyncio
    async def test_writes_nodes_and_relationships_for_full_triple(self):
        fake_neo4j = AsyncMock()
        with patch("backend.database.connection.get_neo4j", return_value=fake_neo4j):
            result = await record_user_host_process(
                user_id="user:alice", host_id="host:WKS-01", process_id="4242", process_name="powershell.exe",
            )

        assert result is True
        assert fake_neo4j.create_entity_node.call_count == 3
        entity_type_args = {call.kwargs["entity_type"] for call in fake_neo4j.create_entity_node.call_args_list}
        assert entity_type_args == {"user", "host", "process"}

        assert fake_neo4j.create_relationship.call_count == 2
        rel_types = {call.kwargs["relationship_type"] for call in fake_neo4j.create_relationship.call_args_list}
        assert rel_types == {"logged_in_to", "contains"}

    @pytest.mark.asyncio
    async def test_never_raises_if_neo4j_write_fails(self):
        fake_neo4j = AsyncMock()
        fake_neo4j.create_entity_node.side_effect = RuntimeError("connection refused")
        with patch("backend.database.connection.get_neo4j", return_value=fake_neo4j):
            result = await record_user_host_process(user_id="u1", host_id="h1")
        assert result is False

    @pytest.mark.asyncio
    async def test_partial_data_only_writes_what_is_available(self):
        fake_neo4j = AsyncMock()
        with patch("backend.database.connection.get_neo4j", return_value=fake_neo4j):
            result = await record_user_host_process(host_id="host:WKS-01")

        assert result is True
        assert fake_neo4j.create_entity_node.call_count == 1
        assert fake_neo4j.create_relationship.call_count == 0


class TestTriageAgentIngestsGraphOnAlert:
    @pytest.mark.asyncio
    async def test_triage_execute_calls_record_user_host_process(self):
        from unittest.mock import MagicMock
        from backend.services.orchestrator import TriageAgent
        from backend.services.investigation_context import InvestigationContext
        from backend.services.llm_client import TriageOutput, Entity

        mock_result = TriageOutput(
            severity="High",
            classification="suspicious_login",
            tactic="Initial Access",
            technique="T1078",
            entities_identified=[Entity(type="host", id="HOST-GRAPH-1")],
            requires_immediate_action=True,
            initial_assessment="Suspicious login on HOST-GRAPH-1.",
            confidence=0.8,
        )
        mock_structured_llm = MagicMock()
        mock_structured_llm.ainvoke = AsyncMock(return_value=mock_result)
        mock_chat = MagicMock()
        mock_chat.with_structured_output.return_value = mock_structured_llm

        agent = TriageAgent()
        context = InvestigationContext(alert_data={
            "alert_id": "alert-graph-1",
            "description": "Suspicious login on HOST-GRAPH-1",
            "user_name": "alice",
            "computer_name": "HOST-GRAPH-1",
        })

        with patch("backend.services.llm_client.get_llm", return_value=mock_chat), \
             patch("backend.services.graph_ingest.record_user_host_process", new=AsyncMock(return_value=True)) as mock_ingest:
            await agent.execute({}, context)

        mock_ingest.assert_awaited_once()
        _, kwargs = mock_ingest.call_args
        assert kwargs["user_id"] == "alice"
        assert kwargs["host_id"] == "HOST-GRAPH-1"


class TestResponseOrchestrationConsultsBlastRadius:
    @pytest.mark.asyncio
    async def test_execute_action_attaches_graph_blast_radius_when_neo4j_configured(self):
        from backend.services.response_orchestration import ResponseOrchestrator
        from backend.services.rca_engine import ResponseAction, ResponseRecommendation

        fake_neo4j = AsyncMock()
        fake_neo4j.get_blast_radius.return_value = {
            "root_entity_id": "HOST-01", "max_hops": 2,
            "reachable_entities": [{"entity_id": "HOST-02", "hops": 1}], "edges": [],
        }

        action = ResponseRecommendation(
            action=ResponseAction.ISOLATE_HOST, priority="critical", target="HOST-01",
            description="Isolate compromised host", prerequisites=[], estimated_time_minutes=5,
            success_criteria=[], rollback_steps=[], business_impact="",
        )

        orchestrator = ResponseOrchestrator(approval_required=False)
        with patch("backend.database.connection.get_neo4j", return_value=fake_neo4j):
            result = await orchestrator._execute_action(action=action, approval_callback=None, phase="containment")

        assert result.get("graph_blast_radius", {}).get("reachable_entities") == [{"entity_id": "HOST-02", "hops": 1}]

    @pytest.mark.asyncio
    async def test_execute_action_omits_blast_radius_when_neo4j_not_configured(self):
        from backend.services.response_orchestration import ResponseOrchestrator
        from backend.services.rca_engine import ResponseAction, ResponseRecommendation

        action = ResponseRecommendation(
            action=ResponseAction.ISOLATE_HOST, priority="critical", target="HOST-01",
            description="Isolate compromised host", prerequisites=[], estimated_time_minutes=5,
            success_criteria=[], rollback_steps=[], business_impact="",
        )

        orchestrator = ResponseOrchestrator(approval_required=False)
        with patch("backend.database.connection.get_neo4j", return_value=None):
            result = await orchestrator._execute_action(action=action, approval_callback=None, phase="containment")

        assert "graph_blast_radius" not in result
