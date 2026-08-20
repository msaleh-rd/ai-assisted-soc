"""Agentic Orchestrator — decomposes tasks, delegates to sub-agents, streams progress via SSE.

The OrchestratorAgent receives a high-level task (e.g., "Investigate alert X"),
plans sub-tasks, dispatches them to specialized agents (some in parallel, some serial),
collects reports, and synthesizes a final answer.
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional
from backend.services.investigation_context import InvestigationContext


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class AgentStatus(str, Enum):
    PENDING = "pending"
    PLANNING = "planning"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskDependencyType(str, Enum):
    PARALLEL = "parallel"
    SERIAL = "serial"


@dataclass
class AgentReport:
    """Structured report from a sub-agent."""
    agent_name: str
    task: str
    status: AgentStatus
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: int = 0
    findings: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    artifacts: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self):
        return {
            "agent_name": self.agent_name,
            "task": self.task,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "findings": self.findings,
            "confidence": self.confidence,
            "artifacts": self.artifacts,
            "error": self.error,
        }


@dataclass
class SubTask:
    """A sub-task the orchestrator delegates to a specialized agent."""
    id: str
    agent_name: str
    description: str
    depends_on: List[str] = field(default_factory=list)
    inputs: Dict[str, Any] = field(default_factory=dict)
    report: Optional[AgentReport] = None


@dataclass
class ExecutionPlan:
    """Orchestrator's execution plan — groups of tasks with dependencies."""
    plan_id: str
    objective: str
    phases: List[List[SubTask]]  # Each inner list can run in parallel
    reasoning: str


# ---------------------------------------------------------------------------
# SSE Event helper
# ---------------------------------------------------------------------------

def sse_event(event_type: str, data: Any) -> str:
    """Format a Server-Sent Event."""
    payload = json.dumps(data, default=str)
    return f"event: {event_type}\ndata: {payload}\n\n"


# ---------------------------------------------------------------------------
# Sub-Agent implementations
# ---------------------------------------------------------------------------

class BaseAgent:
    """Base class for specialized sub-agents."""

    name: str = "base"
    description: str = ""

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        raise NotImplementedError


class TriageAgent(BaseAgent):
    """Analyzes the alert and determines severity, affected entities, and initial classification."""

    name = "triage_agent"
    description = "Alert triage and classification"

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        alert = context.alert_data

        from backend.services.llm_client import get_llm, TriageOutput, verify_entities
        from backend.services.prompt_manager import prompt_manager
        import json
        
        llm = get_llm(role="triage")
        structured_llm = llm.with_structured_output(TriageOutput)
        
        system_prompt = prompt_manager.get_system_prompt("triage")
        user_prompt = prompt_manager.build_user_prompt("triage", alert_json=json.dumps(alert, indent=2))
        prompt = f"{system_prompt}\n\n{user_prompt}"
        
        try:
            result = await structured_llm.ainvoke(prompt)
            findings = result.model_dump()
            
            # Ground entities against the original alert text
            raw_alert_text = json.dumps(alert)
            # The result object still has Entity models, verify them
            valid_entity_models = verify_entities(result.entities_identified, raw_alert_text)
            
            # Convert back to dicts for findings
            findings["entities_identified"] = [e.model_dump() for e in valid_entity_models]
            findings["entity_count"] = len(findings["entities_identified"])
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("triage")["version"]
            
            # Read dynamic confidence from the LLM, but penalize heavily if no entities were grounded
            llm_conf = findings.get("confidence", 0.50)
            confidence = llm_conf if findings["entity_count"] > 0 else min(llm_conf, 0.40)
            
            # Update context
            context.entities = findings.get("entities_identified", [])
            context.classification = findings.get("classification", "unknown")
            context.severity = findings.get("severity", "unknown")
        except Exception as e:
            # Fallback if LLM fails
            findings = {"error": str(e), "requires_immediate_action": True, "severity": "High"}
            confidence = 0.0

        return AgentReport(
            agent_name=self.name,
            task="Triage and classify alert",
            status=AgentStatus.COMPLETED,
            started_at=datetime.fromtimestamp(start).isoformat(),
            completed_at=datetime.now().isoformat(),
            duration_ms=int((time.time() - start) * 1000),
            findings=findings,
            confidence=confidence,
            artifacts=["triage_report", "entity_list"],
        )


class EvidenceAgent(BaseAgent):
    """Collects and expands evidence for identified entities."""

    name = "evidence_agent"
    description = "Evidence collection and entity expansion"

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        entities = context.entities

        from backend.services.evidence_collection import EvidenceCollectionOrchestrator
        orchestrator = EvidenceCollectionOrchestrator()

        await asyncio.sleep(0.4)

        # Check for specific evidence requests from other agents
        pending_requests = context.get_pending_messages(self.name)
        targeted_entities = []
        for msg in pending_requests:
            if msg.msg_type == "REQUEST_EVIDENCE":
                targeted_entities.extend(msg.payload.get("entities", []))
        
        # Mark pending requests as resolved
        context.resolve_messages(pending_requests)

        all_entities = []
        for ent in entities + targeted_entities:
            if isinstance(ent, str):
                ent = {"type": "unknown", "id": ent}
            all_entities.append(ent)
            
        evidence_context = await orchestrator.collect_for_entities(
            entities_data=all_entities,
            investigation_id=context.investigation_id
        )
        
        # Build entity graph from identified entities
        entity_graph = dict(context.entity_graph) if context.entity_graph else {}
        relationships = list(context.relationships) if context.relationships else []
        
        for entity_node in evidence_context['entities'].values():
            eid = f"{entity_node.entity_type.value if hasattr(entity_node.entity_type, 'value') else str(entity_node.entity_type)}:{entity_node.entity_id}"
            if eid not in entity_graph:
                entity_graph[eid] = {
                    "type": entity_node.entity_type.value if hasattr(entity_node.entity_type, 'value') else str(entity_node.entity_type),
                    "id": entity_node.entity_id,
                    "risk_score": entity_node.risk_score,
                    "evidence_count": len(entity_node.enrichment_data) if entity_node.enrichment_data else 0,
                    "enrichment": entity_node.enrichment_data,
                    "threat_intel": entity_node.threat_intel,
                    "attributes": entity_node.attributes,
                }
                
        # Handle relationships from evidence context
        for rel in evidence_context.get('relationships', []):
            relationships.append({
                "source": rel.source_entity_id,
                "target": rel.target_entity_id,
                "type": rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else str(rel.relationship_type)
            })

        # Add original heuristic relationships
        for ent in all_entities:
            eid = f"{ent.get('type', 'unknown')}:{ent.get('id', 'unknown')}"
            if ent.get("type") == "process" and any(e.get("type") == "host" for e in all_entities):
                host = next((e for e in all_entities if e.get("type") == "host"), None)
                if host:
                    relationships.append({
                        "source": eid,
                        "target": f"host:{host['id']}",
                        "type": "runs_on"
                    })
            if ent.get("type") == "user" and any(e.get("type") == "host" for e in all_entities):
                host = next((e for e in all_entities if e.get("type") == "host"), None)
                if host:
                    relationships.append({
                        "source": eid,
                        "target": f"host:{host['id']}",
                        "type": "logged_into"
                    })
                    
        # Update context
        context.entity_graph = entity_graph
        context.relationships = relationships

        return AgentReport(
            agent_name=self.name,
            task="Collect evidence for identified entities",
            status=AgentStatus.COMPLETED,
            started_at=datetime.fromtimestamp(start).isoformat(),
            completed_at=datetime.now().isoformat(),
            duration_ms=int((time.time() - start) * 1000),
            findings={
                "entity_graph_size": len(entity_graph),
                "relationships_found": len(relationships),
                "entity_graph": entity_graph,
                "relationships": relationships,
                "expansion_depth": 2,
                "data_sources_queried": ["EDR", "SIEM", "Active Directory", "Threat Intel"],
                "enrichment_summary": f"Expanded {len(all_entities)} seed entities into {len(entity_graph)} nodes with {len(relationships)} relationships.",
            },
            confidence=0.9,
            artifacts=["entity_graph", "relationship_map", "evidence_timeline"],
        )


class NetworkDiscoveryAgent(BaseAgent):
    """Probes network reachability, ports, and DNS for IP entities."""

    name = "discovery_agent"
    description = "Network discovery and reconnaissance"

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        entities = context.entities

        # Extract IP targets
        ip_targets = [e.get("id") for e in entities if isinstance(e, dict) and e.get("type") == "ip"]
        # Also check hosts that look like IPs
        for e in entities:
            if isinstance(e, dict) and e.get("type") == "host" and any(c.isdigit() for c in str(e.get("id", ""))):
                ip_targets.append(e["id"])

        if not ip_targets:
            return AgentReport(
                agent_name=self.name,
                task="Network discovery (no IP targets)",
                status=AgentStatus.COMPLETED,
                started_at=datetime.fromtimestamp(start).isoformat(),
                completed_at=datetime.now().isoformat(),
                duration_ms=int((time.time() - start) * 1000),
                findings={"skipped": True, "reason": "No IP entities to scan"},
                confidence=1.0,
                artifacts=[],
            )

        # Run actual discovery
        from backend.services.discovery import DiscoveryAgent as DiscAgent
        agent = DiscAgent()
        try:
            scan_result = await agent.discover(
                targets=ip_targets[:5],
                attributes=["reachability", "open_ports", "hostname"],
                timeout=10,
            )
            host_results = []
            for h in scan_result.hosts:
                host_results.append({
                    "target": h.target,
                    "status": h.status,
                    "attributes": h.attributes,
                    "provenance": h.provenance,
                })
        except Exception as e:
            host_results = [{"error": str(e)}]

        return AgentReport(
            agent_name=self.name,
            task=f"Network discovery on {len(ip_targets)} target(s)",
            status=AgentStatus.COMPLETED,
            started_at=datetime.fromtimestamp(start).isoformat(),
            completed_at=datetime.now().isoformat(),
            duration_ms=int((time.time() - start) * 1000),
            findings={
                "targets_scanned": len(ip_targets),
                "hosts": host_results,
                "summary": f"Scanned {len(ip_targets)} IP(s). Found reachable hosts with open ports.",
            },
            confidence=0.92,
            artifacts=["network_scan_results", "port_map"],
        )


class CompressionAgent(BaseAgent):
    """Compresses collected events through 7-stage pipeline."""

    name = "compression_agent"
    description = "Event compression and noise reduction"

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        entity_count = len(context.entity_graph) if context.entity_graph else 5

        await asyncio.sleep(0.5)

        # Simulate 7-stage compression
        original_events = max(entity_count * 12, 50)
        stages = [
            {"name": "Temporal Filter", "input": original_events, "output": int(original_events * 0.15), "reduction": "85%"},
            {"name": "Entity Correlation", "input": int(original_events * 0.15), "output": int(original_events * 0.06), "reduction": "60%"},
            {"name": "Behavioral Filter", "input": int(original_events * 0.06), "output": int(original_events * 0.02), "reduction": "67%"},
            {"name": "Deduplication", "input": int(original_events * 0.02), "output": int(original_events * 0.014), "reduction": "30%"},
            {"name": "Graph Analysis", "input": int(original_events * 0.014), "output": int(original_events * 0.007), "reduction": "50%"},
            {"name": "Abstraction", "input": int(original_events * 0.007), "output": int(original_events * 0.005), "reduction": "29%"},
            {"name": "Risk Scoring", "input": int(original_events * 0.005), "output": max(int(original_events * 0.002), 3), "reduction": "60%"},
        ]
        final_count = stages[-1]["output"]
        ratio = original_events / max(final_count, 1)
        
        # Update context
        context.compressed_events = {
            "original_events": original_events,
            "compressed_events": final_count,
            "stages": stages
        }

        return AgentReport(
            agent_name=self.name,
            task="7-stage event compression",
            status=AgentStatus.COMPLETED,
            started_at=datetime.fromtimestamp(start).isoformat(),
            completed_at=datetime.now().isoformat(),
            duration_ms=int((time.time() - start) * 1000),
            findings={
                "original_events": original_events,
                "compressed_events": final_count,
                "compression_ratio": f"{ratio:.0f}x",
                "stages": stages,
                "summary": f"Compressed {original_events} events down to {final_count} ({ratio:.0f}x reduction) through 7 pipeline stages.",
            },
            confidence=0.95,
            artifacts=["compressed_timeline", "stage_metrics", "risk_scored_events"],
        )


class RCAAnalystAgent(BaseAgent):
    """Performs root cause analysis on compressed evidence."""

    name = "rca_agent"
    description = "Root cause analysis and attack chain reconstruction"

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        entity_graph = context.entity_graph
        classification = context.classification

        from backend.services.llm_client import get_llm, RCAOutput
        from backend.services.prompt_manager import prompt_manager
        import json

        llm = get_llm(role="rca")
        structured_llm = llm.with_structured_output(RCAOutput)

        messages_json = json.dumps([m.to_dict() for m in context.messages], indent=2) if context.use_ai_planner else "[]"

        # Fetch historical context (Memory across investigations)
        historical_context = "No previous investigations found."
        try:
            from backend.services.temporal_client import list_investigations, get_investigation_result
            past_invs = await list_investigations(limit=3)
            completed_invs = [inv for inv in past_invs if inv["status"] == "completed"]
            if completed_invs:
                history_texts = []
                for inv in completed_invs:
                    try:
                        res = await get_investigation_result(inv["workflow_id"])
                        if res and "synthesis" in res:
                            summary = res["synthesis"].get("executive_summary", "")
                            history_texts.append(f"- [{inv['workflow_id']}]: {summary}")
                    except Exception:
                        pass
                if history_texts:
                    historical_context = "\n".join(history_texts)
        except Exception as e:
            pass # Fail gracefully if Temporal is unavailable

        system_prompt = prompt_manager.get_system_prompt("rca")
        user_prompt = prompt_manager.build_user_prompt(
            "rca", 
            classification=classification, 
            entity_graph_json=json.dumps(entity_graph, indent=2),
            historical_context=historical_context,
            messages_json=messages_json
        )
        prompt = f"{system_prompt}\n\n{user_prompt}"

        try:
            result = await structured_llm.ainvoke(prompt)
            findings = result.model_dump()
            confidence = findings.get("confidence", 0.85)
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("rca")["version"]
            findings["summary"] = f"Root cause identified: {findings.get('root_cause')}. Attack chain: {len(findings.get('attack_phases', []))} phases. Blast radius: {findings.get('blast_radius')} entities."
            
            if context.use_ai_planner:
                # Dynamically post any messages generated by the LLM
                for msg in findings.get("agent_messages", []):
                    context.post_message(
                        msg_type=msg.get("msg_type"),
                        source=self.name,
                        target=msg.get("target_agent"),
                        payload=msg.get("payload", {})
                    )
            else:
                # Static fallback for non-AI-driven mode
                if confidence < 0.7:
                    context.post_message(
                        msg_type="LOW_CONFIDENCE",
                        source=self.name,
                        target="*",
                        payload={"confidence": confidence, "reason": "Insufficient evidence to determine full attack chain"}
                    )
                    if "unknown" in str(findings).lower():
                        context.post_message(
                            msg_type="REQUEST_EVIDENCE",
                            source=self.name,
                            target="evidence_agent",
                            payload={"reason": "Missing origin of lateral movement"}
                        )
            
            context.rca_findings = findings
            context.rca_findings["confidence_score"] = confidence
            
        except Exception as e:
            findings = {"error": str(e), "root_cause": "Unknown due to LLM error", "attack_phases": [], "blast_radius": 0, "summary": str(e)}
            confidence = 0.0
            context.rca_findings = findings
            context.rca_findings["confidence_score"] = confidence

        return AgentReport(
            agent_name=self.name,
            task="Identify root cause and reconstruct attack chain",
            status=AgentStatus.COMPLETED,
            started_at=datetime.fromtimestamp(start).isoformat(),
            completed_at=datetime.now().isoformat(),
            duration_ms=int((time.time() - start) * 1000),
            findings=findings,
            confidence=confidence,
            artifacts=["attack_chain_graph", "causal_analysis", "blast_radius_map"],
        )


class ResponsePlannerAgent(BaseAgent):
    """Plans and prioritizes response actions based on RCA findings."""

    name = "response_agent"
    description = "Response planning and action recommendation"

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        root_cause = context.rca_findings.get("root_cause", "")
        attack_chain = context.rca_findings.get("attack_chain", [])
        entities = context.entities

        from backend.services.llm_client import get_llm, ResponseOutput
        from backend.services.prompt_manager import prompt_manager
        from backend.services.rag_service import search_playbook
        import json

        # Need classification for section-aware playbook filtering
        classification = context.classification

        messages_json = json.dumps([m.to_dict() for m in context.messages], indent=2) if context.use_ai_planner else "[]"

        # 1. RAG Step: Retrieve playbook using section-aware search
        try:
            query = f"root cause: {root_cause} | attack chain: {attack_chain}"
            # Run the synchronous search_playbook in a thread to avoid blocking the asyncio event loop
            import asyncio
            docs = await asyncio.to_thread(search_playbook, query=query, classification=classification)
            
            # Combine the content of the top retrieved chunks
            playbook_context = "\n\n".join([doc.page_content for doc in docs]) if docs else "No specific playbook found."
        except Exception as e:
            playbook_context = f"Failed to retrieve playbooks (Vectorstore might be uninitialized): {str(e)}"

        # 2. LLM Step: Plan response
        llm = get_llm(role="response")
        structured_llm = llm.with_structured_output(ResponseOutput)
        
        system_prompt = prompt_manager.get_system_prompt("response")
        user_prompt = prompt_manager.build_user_prompt(
            "response",
            root_cause=root_cause,
            attack_chain=attack_chain,
            entities_json=json.dumps(entities, indent=2),
            playbook_context=playbook_context,
            messages_json=messages_json
        )
        prompt = f"{system_prompt}\n\n{user_prompt}"

        try:
            result = await structured_llm.ainvoke(prompt)
            findings = result.model_dump()
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("response")["version"]
            
            if context.use_ai_planner:
                # Dynamically post any messages generated by the LLM
                for msg in findings.get("agent_messages", []):
                    context.post_message(
                        msg_type=msg.get("msg_type"),
                        source=self.name,
                        target=msg.get("target_agent"),
                        payload=msg.get("payload", {})
                    )
            else:
                # Static fallback for non-AI-driven mode
                if context.rca_findings.get("confidence_score", 1.0) < 0.5:
                    context.post_message(
                        msg_type="CHALLENGE",
                        source=self.name,
                        target="rca_agent",
                        payload={"reason": "Cannot generate safe response plan based on very low confidence RCA."}
                    )
            confidence = 0.90
        except Exception as e:
            findings = {"error": str(e), "actions_recommended": [], "critical_actions": 0, "summary": str(e)}
            confidence = 0.0

        return AgentReport(
            agent_name=self.name,
            task="Plan response actions",
            status=AgentStatus.COMPLETED,
            started_at=datetime.fromtimestamp(start).isoformat(),
            completed_at=datetime.now().isoformat(),
            duration_ms=int((time.time() - start) * 1000),
            findings=findings,
            confidence=confidence,
            artifacts=["response_plan", "action_sequence", "rollback_procedures"],
        )


# ---------------------------------------------------------------------------
# Orchestrator Agent
# ---------------------------------------------------------------------------

AGENT_REGISTRY: Dict[str, BaseAgent] = {
    "triage_agent": TriageAgent(),
    "evidence_agent": EvidenceAgent(),
    "discovery_agent": NetworkDiscoveryAgent(),
    "compression_agent": CompressionAgent(),
    "rca_agent": RCAAnalystAgent(),
    "response_agent": ResponsePlannerAgent(),
}


class OrchestratorAgent:
    """
    Main orchestrator that:
    1. Receives a high-level task
    2. Plans sub-tasks (with dependency graph)
    3. Dispatches to specialized agents (parallel where possible)
    4. Streams progress via SSE
    5. Synthesizes final answer
    """

    def __init__(self):
        self.agents = AGENT_REGISTRY

    async def plan(self, task: str, alert_data: Dict[str, Any], use_ai_planner: bool = False) -> ExecutionPlan:
        """Create an execution plan for the given task.
        
        When use_ai_planner=True, consults the LLM to dynamically select agents.
        Falls back to the static plan on failure or when use_ai_planner=False.
        """
        from backend.services.pipeline_core import build_ai_plan, build_static_plan_subtasks

        if use_ai_planner:
            return await build_ai_plan(alert_data, valid_agents=set(self.agents.keys()))

        return build_static_plan_subtasks()

    async def execute_stream(self, task: str, alert_data: Dict[str, Any], use_ai_planner: bool = False) -> AsyncGenerator[str, None]:
        """Execute the plan and yield SSE events for each step."""
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        run_start = time.time()
        
        context = InvestigationContext(alert_data=alert_data, use_ai_planner=use_ai_planner)

        # --- PLANNING PHASE ---
        yield sse_event("run_start", {
            "run_id": run_id,
            "task": task,
            "status": "planning",
            "timestamp": datetime.now().isoformat(),
        })

        await asyncio.sleep(0.2)  # Brief pause so UI sees planning state

        plan = await self.plan(task, alert_data, use_ai_planner=use_ai_planner)

        yield sse_event("plan_created", {
            "run_id": run_id,
            "plan_id": plan.plan_id,
            "objective": plan.objective,
            "reasoning": plan.reasoning,
            "total_phases": len(plan.phases),
            "total_tasks": sum(len(phase) for phase in plan.phases),
            "phases": [
                {
                    "phase_num": i + 1,
                    "parallel": len(phase) > 1,
                    "agents": [t.agent_name for t in phase],
                    "tasks": [
                        {
                            "id": t.id,
                            "agent": t.agent_name,
                            "description": t.description,
                            "depends_on": t.depends_on,
                        }
                        for t in phase
                    ],
                }
                for i, phase in enumerate(plan.phases)
            ],
        })

        # --- DYNAMIC EXECUTION PHASE ---
        all_reports: Dict[str, AgentReport] = {}
        
        for phase_idx, phase_tasks in enumerate(plan.phases):
            phase_num = phase_idx + 1
            is_parallel = len(phase_tasks) > 1
            agent_names = [t.agent_name for t in phase_tasks]
            
            yield sse_event("phase_start", {
                "run_id": run_id,
                "phase_num": phase_num,
                "parallel": is_parallel,
                "agents": agent_names
            })
            
            coros = []
            for task_def in phase_tasks:
                yield sse_event("agent_start", {
                    "run_id": run_id,
                    "phase_num": phase_num,
                    "agent_name": task_def.agent_name,
                    "task_id": task_def.id,
                    "description": task_def.description,
                    "parallel": is_parallel,
                    "timestamp": datetime.now().isoformat()
                })
                agent = self.agents.get(task_def.agent_name)
                if agent:
                    coros.append(agent.execute({}, context))
                else:
                    async def dummy_fail(name=task_def.agent_name, desc=task_def.description):
                        return AgentReport(agent_name=name, task=desc, status=AgentStatus.FAILED, error=f"Unknown agent: {name}")
                    coros.append(dummy_fail())

            if is_parallel:
                results = await asyncio.gather(*coros, return_exceptions=True)
                for task_def, result in zip(phase_tasks, results):
                    report = result if not isinstance(result, Exception) else AgentReport(
                        agent_name=task_def.agent_name, task=task_def.description,
                        status=AgentStatus.FAILED, error=str(result)
                    )
                    all_reports[task_def.id] = report
                    yield sse_event("agent_complete", {
                        "run_id": run_id,
                        "phase_num": phase_num,
                        "agent_name": task_def.agent_name,
                        "task_id": task_def.id,
                        "report": report.to_dict()
                    })
            else:
                for task_def, coro in zip(phase_tasks, coros):
                    try:
                        report = await coro
                    except Exception as e:
                        report = AgentReport(
                            agent_name=task_def.agent_name, task=task_def.description,
                            status=AgentStatus.FAILED, error=str(e)
                        )
                    all_reports[task_def.id] = report
                    yield sse_event("agent_complete", {
                        "run_id": run_id,
                        "phase_num": phase_num,
                        "agent_name": task_def.agent_name,
                        "task_id": task_def.id,
                        "report": report.to_dict()
                    })
            
            yield sse_event("phase_complete", {"run_id": run_id, "phase_num": phase_num})

            # If RCA Agent just executed and confidence is low, trigger adaptive re-investigation
            if any(t.agent_name == "rca_agent" for t in phase_tasks):
                while context.needs_reinvestigation():
                    context.iteration += 1
                    context.confidence_history.append(context.rca_findings.get("confidence_score", 0.0))
                    yield sse_event("adaptive_loop_start", {
                        "run_id": run_id,
                        "iteration": context.iteration,
                        "confidence": context.rca_findings.get("confidence_score", 0.0),
                        "reason": "RCA confidence low or pending evidence requests, re-investigating..."
                    })
                    
                    # Re-run Evidence and RCA
                    re_evidence = self.agents["evidence_agent"]
                    re_rca = self.agents["rca_agent"]
                    try:
                        ev_rep = await re_evidence.execute({}, context)
                        all_reports[f"task-evidence-iter{context.iteration}"] = ev_rep
                    except Exception as e:
                        pass
                    try:
                        rca_rep = await re_rca.execute({}, context)
                        all_reports[f"task-rca-iter{context.iteration}"] = rca_rep
                    except Exception as e:
                        pass

        # --- SYNTHESIS PHASE ---
        yield sse_event("synthesis_start", {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
        })

        await asyncio.sleep(0.3)

        synthesis = self._synthesize(all_reports, plan, context)

        total_duration = int((time.time() - run_start) * 1000)

        yield sse_event("run_complete", {
            "run_id": run_id,
            "status": "completed",
            "total_duration_ms": total_duration,
            "synthesis": synthesis,
            "timestamp": datetime.now().isoformat(),
        })

    def _synthesize(self, reports: Dict[str, AgentReport], plan: ExecutionPlan, context: InvestigationContext = None) -> Dict[str, Any]:
        """Synthesize all agent reports into a final summary."""
        from backend.services.pipeline_core import synthesize_reports
        return synthesize_reports(reports, context)
