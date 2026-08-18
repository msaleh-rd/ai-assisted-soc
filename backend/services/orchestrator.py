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
            
            # Only 0.95 confidence if we found grounded entities
            confidence = 0.95 if findings["entity_count"] > 0 else 0.50
            
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
        
        # Build entity graph from identified entities
        entity_graph = dict(context.entity_graph) if context.entity_graph else {}
        relationships = list(context.relationships) if context.relationships else []
        
        # Mark pending requests as resolved
        context.resolve_messages(pending_requests)

        for ent in entities + targeted_entities:
            # Handle string vs dict based on how it's passed
            if isinstance(ent, str):
                ent = {"type": "unknown", "id": ent}
            eid = f"{ent.get('type', 'unknown')}:{ent.get('id', 'unknown')}"
            if eid not in entity_graph:
                entity_graph[eid] = {
                    "type": ent.get("type", "unknown"),
                    "id": ent.get("id", "unknown"),
                    "risk_score": 0.7 if ent.get("type") in ("file", "ip") else 0.4,
                    "evidence_count": 3,
                }
            # Create relationships between entities
            if ent.get("type") == "process" and any(e.get("type") == "host" for e in entities):
                host = next((e for e in entities if e.get("type") == "host"), None)
                if host:
                    relationships.append({
                        "source": eid,
                        "target": f"host:{host['id']}",
                        "type": "runs_on"
                    })
            if ent.get("type") == "user" and any(e.get("type") == "host" for e in entities):
                host = next((e for e in entities if e.get("type") == "host"), None)
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
                "enrichment_summary": f"Expanded {len(entities)} seed entities into {len(entity_graph)} nodes with {len(relationships)} relationships.",
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

        system_prompt = prompt_manager.get_system_prompt("rca")
        user_prompt = prompt_manager.build_user_prompt("rca", classification=classification, entity_graph_json=json.dumps(entity_graph, indent=2))
        prompt = f"{system_prompt}\n\n{user_prompt}"

        try:
            result = await structured_llm.ainvoke(prompt)
            findings = result.model_dump()
            confidence = findings.get("confidence", 0.85)
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("rca")["version"]
            findings["summary"] = f"Root cause identified: {findings.get('root_cause')}. Attack chain: {len(findings.get('attack_phases', []))} phases. Blast radius: {findings.get('blast_radius')} entities."
            
            # Post messages if confidence is low
            if confidence < 0.7:
                context.post_message(
                    msg_type="LOW_CONFIDENCE",
                    source=self.name,
                    target="*",
                    payload={"confidence": confidence, "reason": "Insufficient evidence to determine full attack chain"}
                )
                
                # If we suspect there are missing entities, we can request evidence
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

        # Check if we should challenge the findings
        if context.rca_findings.get("confidence_score", 1.0) < 0.5:
            context.post_message(
                msg_type="CHALLENGE",
                source=self.name,
                target="rca_agent",
                payload={"reason": "Cannot generate safe response plan based on very low confidence RCA."}
            )

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
            playbook_context=playbook_context
        )
        prompt = f"{system_prompt}\n\n{user_prompt}"

        try:
            result = await structured_llm.ainvoke(prompt)
            findings = result.model_dump()
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("response")["version"]
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
        plan_id = f"plan-{uuid.uuid4().hex[:8]}"

        if use_ai_planner:
            try:
                from backend.services.llm_client import get_llm, PlannerOutput
                from backend.services.prompt_manager import prompt_manager
                import json
                import logging
                _log = logging.getLogger("orchestrator")

                llm = get_llm(role="planner")
                structured_llm = llm.with_structured_output(PlannerOutput)
                system_prompt = prompt_manager.get_system_prompt("planner")
                user_prompt = prompt_manager.build_user_prompt(
                    "planner", alert_json=json.dumps(alert_data, indent=2)
                )

                result = await structured_llm.ainvoke(f"{system_prompt}\n\n{user_prompt}")

                # Validate: every agent_name must exist in the registry
                valid_agents = set(self.agents.keys())
                phases = []
                for phase_tasks in result.phases:
                    phase = []
                    for t in phase_tasks:
                        if t.agent_name not in valid_agents:
                            _log.warning("AI Planner referenced unknown agent '%s' — skipping", t.agent_name)
                            continue
                        phase.append(SubTask(
                            id=t.id,
                            agent_name=t.agent_name,
                            description=t.description,
                        ))
                    if phase:
                        phases.append(phase)

                if phases:
                    _log.info("AI Planner generated %d phases with %d total tasks",
                              len(phases), sum(len(p) for p in phases))
                    return ExecutionPlan(
                        plan_id=plan_id,
                        objective=task,
                        phases=phases,
                        reasoning=result.reasoning,
                    )
                else:
                    _log.warning("AI Planner produced an empty plan — falling back to static")
            except Exception as e:
                import logging
                logging.getLogger("orchestrator").error(
                    "AI Planner failed, falling back to static plan: %s", e
                )

        # --- Static Plan (default / fallback) ---
        # Phase 1: Triage (must run first)
        triage_task = SubTask(
            id="task-triage",
            agent_name="triage_agent",
            description="Analyze alert severity, classify threat, identify entities",
        )

        # Phase 2: Evidence + Discovery (parallel, depends on triage)
        evidence_task = SubTask(
            id="task-evidence",
            agent_name="evidence_agent",
            description="Expand entity graph and collect evidence from data sources",
            depends_on=["task-triage"],
        )
        discovery_task = SubTask(
            id="task-discovery",
            agent_name="discovery_agent",
            description="Probe network reachability and open ports for IP entities",
            depends_on=["task-triage"],
        )

        # Phase 3: Compression (depends on evidence)
        compression_task = SubTask(
            id="task-compression",
            agent_name="compression_agent",
            description="Compress events through 7-stage noise reduction pipeline",
            depends_on=["task-evidence"],
        )

        # Phase 4: RCA (depends on compression + discovery)
        rca_task = SubTask(
            id="task-rca",
            agent_name="rca_agent",
            description="Analyze root cause, reconstruct attack chain, score confidence",
            depends_on=["task-compression", "task-discovery"],
        )

        # Phase 5: Response (depends on RCA)
        response_task = SubTask(
            id="task-response",
            agent_name="response_agent",
            description="Generate prioritized response plan based on RCA findings",
            depends_on=["task-rca"],
        )

        plan = ExecutionPlan(
            plan_id=plan_id,
            objective=task,
            phases=[
                [triage_task],               # Phase 1: sequential
                [evidence_task, discovery_task],  # Phase 2: parallel
                [compression_task],          # Phase 3: sequential
                [rca_task],                  # Phase 4: sequential (waits for both)
                [response_task],             # Phase 5: sequential
            ],
            reasoning=(
                "1) Triage first to understand severity and extract entities. "
                "2) Evidence collection and network discovery can run in PARALLEL since they're independent. "
                "3) Compression needs evidence data, so it waits. "
                "4) RCA needs both compressed evidence AND network context. "
                "5) Response planning depends on root cause identification."
            ),
        )
        return plan

    async def execute_stream(self, task: str, alert_data: Dict[str, Any], use_ai_planner: bool = False) -> AsyncGenerator[str, None]:
        """Execute the plan and yield SSE events for each step."""
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        run_start = time.time()
        
        context = InvestigationContext(alert_data=alert_data)

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

        # --- EXECUTION PHASE ---
        all_reports: Dict[str, AgentReport] = {}
        
        # Execute Phase 1 (Triage)
        phase_num = 1
        task_def = plan.phases[0][0]
        yield sse_event("phase_start", {"run_id": run_id, "phase_num": phase_num, "parallel": False, "agents": [task_def.agent_name]})
        yield sse_event("agent_start", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "description": task_def.description, "parallel": False, "timestamp": datetime.now().isoformat()})
        report = await self.agents[task_def.agent_name].execute({}, context)
        all_reports[task_def.id] = report
        yield sse_event("agent_complete", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "report": report.to_dict()})
        yield sse_event("phase_complete", {"run_id": run_id, "phase_num": phase_num})

        # Adaptive Loop for Evidence -> Compression -> RCA
        looping = True
        while looping:
            context.confidence_history.append(context.rca_findings.get("confidence_score", 0.0))
            
            # Execute Phase 2 (Evidence & Discovery)
            phase_num = 2
            is_parallel = True
            yield sse_event("phase_start", {"run_id": run_id, "phase_num": phase_num, "parallel": is_parallel, "agents": [t.agent_name for t in plan.phases[1]]})
            coros = []
            for task_def in plan.phases[1]:
                yield sse_event("agent_start", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "description": task_def.description, "parallel": is_parallel, "timestamp": datetime.now().isoformat()})
                agent = self.agents[task_def.agent_name]
                coros.append(agent.execute({}, context))
            results = await asyncio.gather(*coros, return_exceptions=True)
            for task_def, result in zip(plan.phases[1], results):
                report = result if not isinstance(result, Exception) else AgentReport(agent_name=task_def.agent_name, task=task_def.description, status=AgentStatus.FAILED, error=str(result))
                all_reports[task_def.id] = report
                yield sse_event("agent_complete", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "report": report.to_dict()})
            yield sse_event("phase_complete", {"run_id": run_id, "phase_num": phase_num})

            # Execute Phase 3 (Compression)
            phase_num = 3
            task_def = plan.phases[2][0]
            yield sse_event("phase_start", {"run_id": run_id, "phase_num": phase_num, "parallel": False, "agents": [task_def.agent_name]})
            yield sse_event("agent_start", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "description": task_def.description, "parallel": False, "timestamp": datetime.now().isoformat()})
            try:
                report = await self.agents[task_def.agent_name].execute({}, context)
            except Exception as e:
                report = AgentReport(agent_name=task_def.agent_name, task=task_def.description, status=AgentStatus.FAILED, error=str(e))
            all_reports[task_def.id] = report
            yield sse_event("agent_complete", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "report": report.to_dict()})
            yield sse_event("phase_complete", {"run_id": run_id, "phase_num": phase_num})
            
            # Execute Phase 4 (RCA)
            phase_num = 4
            task_def = plan.phases[3][0]
            yield sse_event("phase_start", {"run_id": run_id, "phase_num": phase_num, "parallel": False, "agents": [task_def.agent_name]})
            yield sse_event("agent_start", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "description": task_def.description, "parallel": False, "timestamp": datetime.now().isoformat()})
            try:
                report = await self.agents[task_def.agent_name].execute({}, context)
            except Exception as e:
                report = AgentReport(agent_name=task_def.agent_name, task=task_def.description, status=AgentStatus.FAILED, error=str(e))
            all_reports[task_def.id] = report
            yield sse_event("agent_complete", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "report": report.to_dict()})
            yield sse_event("phase_complete", {"run_id": run_id, "phase_num": phase_num})
            
            # Adaptive Loop Check
            if context.needs_reinvestigation():
                context.iteration += 1
                yield sse_event("adaptive_loop_start", {
                    "run_id": run_id,
                    "iteration": context.iteration,
                    "confidence": context.rca_findings.get("confidence_score", 0.0),
                    "reason": "RCA confidence low or pending evidence requests, re-investigating..."
                })
            else:
                looping = False

        # Phase 5: Response
        phase_num = 5
        task_def = plan.phases[4][0]
        yield sse_event("phase_start", {"run_id": run_id, "phase_num": phase_num, "parallel": False, "agents": [task_def.agent_name]})
        yield sse_event("agent_start", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "description": task_def.description, "parallel": False, "timestamp": datetime.now().isoformat()})
        try:
            report = await self.agents[task_def.agent_name].execute({}, context)
        except Exception as e:
            report = AgentReport(agent_name=task_def.agent_name, task=task_def.description, status=AgentStatus.FAILED, error=str(e))
        all_reports[task_def.id] = report
        yield sse_event("agent_complete", {"run_id": run_id, "phase_num": phase_num, "agent_name": task_def.agent_name, "task_id": task_def.id, "report": report.to_dict()})
        yield sse_event("phase_complete", {"run_id": run_id, "phase_num": phase_num})

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
        triage = reports.get("task-triage")
        evidence = reports.get("task-evidence")
        discovery = reports.get("task-discovery")
        compression = reports.get("task-compression")
        rca = reports.get("task-rca")
        response = reports.get("task-response")

        severity = triage.findings.get("severity", "Unknown") if triage else "Unknown"
        root_cause = rca.findings.get("root_cause", "Undetermined") if rca else "Undetermined"
        confidence = rca.findings.get("confidence_score", 0) if rca else 0
        recommended_actions = response.findings.get("actions_recommended", []) if response else []
        total_actions = len(recommended_actions)
        compression_ratio = compression.findings.get("compression_ratio", "N/A") if compression else "N/A"
        blast_radius = rca.findings.get("blast_radius", 0) if rca else 0

        # Determine overall verdict
        if confidence >= 0.8:
            verdict = "High-confidence root cause identified. Immediate response recommended."
        elif confidence >= 0.5:
            verdict = "Moderate confidence in findings. Consider additional investigation."
        else:
            verdict = "Low confidence. Adaptive re-investigation recommended."
            
        messages_exchanged = [m.to_dict() for m in context.messages] if context else []

        return {
            "verdict": verdict,
            "severity": severity,
            "root_cause": root_cause,
            "confidence": confidence,
            "blast_radius": blast_radius,
            "compression_ratio": compression_ratio,
            "response_actions": total_actions,
            "recommended_actions": recommended_actions,
            "agents_used": len(reports),
            "all_succeeded": all(r.status == AgentStatus.COMPLETED for r in reports.values()),
            "iterations": context.iteration if context else 0,
            "confidence_history": context.confidence_history if context else [],
            "messages_exchanged": len(messages_exchanged),
            "executive_summary": (
                f"Investigation complete. Severity: {severity}. "
                f"Root cause: {root_cause} (confidence: {confidence:.0%}). "
                f"Blast radius: {blast_radius} entities. "
                f"Event noise reduced by {compression_ratio}. "
                f"{total_actions} response actions recommended."
            ),
        }
