"""Temporal Workflow and Activities for SOC Investigation Orchestration.

Wraps the existing agent-based orchestrator into durable Temporal Workflows.
Each sub-agent becomes a Temporal Activity; the overall investigation
becomes an InvestigationWorkflow with phased execution.
"""

import asyncio
import uuid
import time
from dataclasses import dataclass, field, asdict
from datetime import timedelta, datetime
from typing import Any, Dict, List, Optional

from temporalio import activity, workflow
from temporalio.common import RetryPolicy

# -- We must use the sandbox-safe imports inside workflow code.
# -- Activities run outside the sandbox and can import anything.

# ============================================================
# Shared data-transfer objects (must be serialisable)
# ============================================================

@dataclass
class AgentReportDTO:
    """Serialisable mirror of orchestrator.AgentReport for Temporal payloads."""
    agent_name: str
    task: str
    status: str  # "completed" | "failed"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: int = 0
    findings: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    artifacts: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class InvestigationInput:
    """Input payload for an investigation workflow."""
    task: str
    alert_data: Dict[str, Any]
    use_ai_planner: bool = False


@dataclass
class PhaseProgress:
    """Tracks a single execution phase."""
    phase_num: int
    parallel: bool
    agents: List[str]
    status: str  # "pending" | "running" | "completed"
    reports: List[AgentReportDTO] = field(default_factory=dict)


@dataclass
class InvestigationProgress:
    """Queryable progress state for a running investigation."""
    run_id: str
    status: str  # "planning" | "running" | "completed" | "failed"
    current_phase: int
    total_phases: int
    plan_reasoning: str = ""
    phases: List[Dict[str, Any]] = field(default_factory=list)
    completed_reports: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    synthesis: Optional[Dict[str, Any]] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    total_duration_ms: int = 0
    iteration: int = 0
    confidence_history: List[float] = field(default_factory=list)
    messages: List[Dict[str, Any]] = field(default_factory=list)


# ============================================================
# Activities — thin wrappers around existing agent classes
# ============================================================

def _agent_report_to_dto(report) -> AgentReportDTO:
    """Convert an orchestrator.AgentReport to a serialisable DTO."""
    return AgentReportDTO(
        agent_name=report.agent_name,
        task=report.task,
        status=report.status.value,
        started_at=report.started_at,
        completed_at=report.completed_at,
        duration_ms=report.duration_ms,
        findings=report.findings,
        confidence=report.confidence,
        artifacts=report.artifacts,
        error=report.error,
    )


# Map from agent registry names → Temporal activity names
AGENT_TO_ACTIVITY = {
    "triage_agent": "triage_activity",
    "evidence_agent": "evidence_activity",
    "discovery_agent": "discovery_activity",
    "compression_agent": "compression_activity",
    "rca_agent": "rca_activity",
    "response_agent": "response_activity",
}


@activity.defn(name="planner_activity")
async def planner_activity(alert_data: Dict[str, Any]) -> List[List[Dict]]:
    """Run the AI Planner to generate a dynamic execution plan.
    
    Returns a plan in the same shape as _build_plan():
    List[List[Dict]] where each Dict has id, agent, activity, description.
    """
    from backend.services.orchestrator import OrchestratorAgent
    agent = OrchestratorAgent()
    plan = await agent.plan("Investigate security alert", alert_data, use_ai_planner=True)

    temporal_plan = []
    for phase in plan.phases:
        temporal_phase = []
        for task in phase:
            activity_name = AGENT_TO_ACTIVITY.get(task.agent_name)
            if not activity_name:
                continue
            temporal_phase.append({
                "id": task.id,
                "agent": task.agent_name,
                "activity": activity_name,
                "description": task.description,
            })
        if temporal_phase:
            temporal_plan.append(temporal_phase)
    return temporal_plan


@activity.defn(name="triage_activity")
async def triage_activity(context_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Run the TriageAgent on the alert data."""
    from backend.services.orchestrator import TriageAgent
    from backend.services.investigation_context import InvestigationContext
    context = InvestigationContext.from_dict(context_dict)
    agent = TriageAgent()
    report = await agent.execute({}, context)
    return {"report": asdict(_agent_report_to_dto(report)), "context": context.to_dict()}


@activity.defn(name="evidence_activity")
async def evidence_activity(context_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Run the EvidenceAgent to expand entity graph."""
    from backend.services.orchestrator import EvidenceAgent
    from backend.services.investigation_context import InvestigationContext
    context = InvestigationContext.from_dict(context_dict)
    agent = EvidenceAgent()
    report = await agent.execute({}, context)
    return {"report": asdict(_agent_report_to_dto(report)), "context": context.to_dict()}


@activity.defn(name="discovery_activity")
async def discovery_activity(context_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Run the NetworkDiscoveryAgent."""
    from backend.services.orchestrator import NetworkDiscoveryAgent
    from backend.services.investigation_context import InvestigationContext
    context = InvestigationContext.from_dict(context_dict)
    agent = NetworkDiscoveryAgent()
    report = await agent.execute({}, context)
    return {"report": asdict(_agent_report_to_dto(report)), "context": context.to_dict()}


@activity.defn(name="compression_activity")
async def compression_activity(context_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Run the CompressionAgent (7-stage pipeline)."""
    from backend.services.orchestrator import CompressionAgent
    from backend.services.investigation_context import InvestigationContext
    context = InvestigationContext.from_dict(context_dict)
    agent = CompressionAgent()
    report = await agent.execute({}, context)
    return {"report": asdict(_agent_report_to_dto(report)), "context": context.to_dict()}


@activity.defn(name="rca_activity")
async def rca_activity(context_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Run the RCAAnalystAgent."""
    from backend.services.orchestrator import RCAAnalystAgent
    from backend.services.investigation_context import InvestigationContext
    context = InvestigationContext.from_dict(context_dict)
    agent = RCAAnalystAgent()
    report = await agent.execute({}, context)
    return {"report": asdict(_agent_report_to_dto(report)), "context": context.to_dict()}


@activity.defn(name="response_activity")
async def response_activity(context_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Run the ResponsePlannerAgent."""
    from backend.services.orchestrator import ResponsePlannerAgent
    from backend.services.investigation_context import InvestigationContext
    context = InvestigationContext.from_dict(context_dict)
    agent = ResponsePlannerAgent()
    report = await agent.execute({}, context)
    return {"report": asdict(_agent_report_to_dto(report)), "context": context.to_dict()}


@activity.defn(name="persist_investigation_results_activity")
async def persist_investigation_results_activity(progress_dict: Dict[str, Any]) -> str:
    """Save the final investigation results to Postgres and Neo4j."""
    from backend.database.connection import get_db, get_neo4j
    from backend.database.postgres import InvestigationRecord, RCAResultRecord
    import contextlib
    
    run_id = progress_dict.get("run_id")
    synthesis = progress_dict.get("synthesis", {})
    reports = progress_dict.get("completed_reports", {})
    
    # 1. Postgres Persistence
    with contextlib.closing(next(get_db())) as db:
        # Create Investigation Record
        inv_record = InvestigationRecord(
            investigation_id=run_id,
            status=progress_dict.get("status", "completed"),
            risk_score=synthesis.get("severity_score", 0.0),
            raw_events_count=len(reports.get("task-evidence", {}).get("findings", {}).get("raw_events", [])),
            compressed_events_count=reports.get("task-compression", {}).get("findings", {}).get("compressed_events", 0)
        )
        db.merge(inv_record)
        
        # Save RCA if it exists
        rca_report = reports.get("task-rca", {})
        if rca_report and rca_report.get("status") == "completed":
            rca_record = RCAResultRecord(
                rca_id=f"rca-{run_id}",
                investigation_id=run_id,
                root_cause=rca_report.get("findings", {}).get("root_cause", ""),
                attack_chain=rca_report.get("findings", {}).get("attack_chain", []),
                confidence=rca_report.get("confidence", 0.0)
            )
            db.merge(rca_record)
            
        db.commit()
    
    # 2. Neo4j Persistence
    neo4j = get_neo4j()
    if neo4j:
        triage = reports.get("task-triage", {})
        entities = triage.get("findings", {}).get("entities_identified", [])
        
        for ent in entities:
            ent_id = ent.get("id") or ent.get("name")
            if ent_id:
                try:
                    await neo4j.create_entity_node(
                        entity_id=ent_id,
                        entity_type=ent.get("type", "unknown"),
                        attributes={"investigation_id": run_id, "name": ent.get("name")}
                    )
                except Exception as e:
                    # Log but continue
                    pass
                
    return f"Persisted investigation {run_id}"

@activity.defn(name="execute_response_activity")
async def execute_response_activity(run_id: str, response_report: Dict[str, Any]) -> str:
    """Execute the response plan using ActionExecutor."""
    from backend.services.response_orchestration import ResponseOrchestrator
    from backend.services.rca_engine import RCAResult, ResponseAction
    from dataclasses import dataclass
    
    # Reconstruct RCA Result for the executor
    findings = response_report.get("findings", {})
    
    # We must mock an RCAResult because execute_response_plan expects it
    @dataclass
    class ResponsePlanAction:
        action: ResponseAction
        target: str
        description: str
        priority: str
        business_impact: str
        prerequisites: List[str]

    @dataclass
    class MockRCAResult:
        immediate_actions: List[Any]
        long_term_remediation: List[Any]
        
    actions = []
    actions = []
    for item in findings.get("actions_recommended", []):
        try:
            action_enum = ResponseAction(item.get("action_type", "isolate_host"))
        except ValueError:
            action_enum = ResponseAction.ISOLATE_HOST
            
        actions.append(ResponsePlanAction(
            action=action_enum,
            target=item.get("target", "Unknown"),
            description=item.get("description", "No description provided"),
            priority=item.get("priority", "high").lower(),
            business_impact="medium",
            prerequisites=[]
        ))
        
    mock_rca = MockRCAResult(immediate_actions=actions, long_term_remediation=[])
    
    # Use real executor
    orchestrator = ResponseOrchestrator(approval_required=False) # We already got approval
    result = await orchestrator.execute_response_plan(mock_rca)
    
    # Log to Audit
    from backend.database.connection import get_db
    from backend.database.postgres import AuditRecord
    import contextlib
    import uuid
    from datetime import datetime
    
    with contextlib.closing(next(get_db())) as db:
        for executed in result.get('actions_executed', []):
            db.add(AuditRecord(
                audit_id=str(uuid.uuid4()),
                investigation_id=run_id,
                action=executed.get('action_type', 'unknown'),
                actor="Human Admin",
                details=f"Executed on target {executed.get('target', 'unknown')}",
                timestamp=datetime.utcnow()
            ))
        db.commit()
        
    return f"Executed {len(result.get('actions_executed', []))} actions"

# Map of activity names to functions (used by the worker to register)
ALL_ACTIVITIES = [
    planner_activity,
    triage_activity,
    evidence_activity,
    discovery_activity,
    compression_activity,
    rca_activity,
    response_activity,
    persist_investigation_results_activity,
    execute_response_activity,
]


@workflow.defn(name="InvestigationWorkflow")
class InvestigationWorkflow:
    """
    Durable investigation workflow that:
    1. Plans sub-tasks from the alert (same logic as OrchestratorAgent)
    2. Executes each phase by invoking Activity functions
    3. Runs parallel activities within a phase via asyncio.gather
    4. Stores progress queryable via Temporal Queries
    5. Synthesises final result
    """

    def __init__(self):
        self._progress = InvestigationProgress(
            run_id="",
            status="pending",
            current_phase=0,
            total_phases=0,
        )
        self._approval_decision: Optional[str] = None
        self._approval_comment: Optional[str] = None

    @workflow.query(name="get_progress")
    def get_progress(self) -> Dict[str, Any]:
        """Return current investigation progress (called by API via Temporal Query)."""
        return asdict(self._progress)
        
    @workflow.signal(name="approve_response")
    def approve_response(self, decision: str, comment: str = "") -> None:
        """Signal to approve or reject the response plan."""
        self._approval_decision = decision
        self._approval_comment = comment

    @workflow.run
    async def run(self, input: InvestigationInput) -> Dict[str, Any]:
        run_id = f"run-{workflow.info().workflow_id[:8]}"
        run_start = workflow.now()

        from backend.services.investigation_context import InvestigationContext
        context = InvestigationContext(alert_data=input.alert_data)
        context_dict = context.to_dict()

        self._progress.run_id = run_id
        self._progress.status = "planning"
        self._progress.started_at = run_start.isoformat()

        # ---- PLANNING ----
        if input.use_ai_planner:
            # AI Planner: call the planner activity to get a dynamic plan
            plan = await workflow.execute_activity(
                "planner_activity",
                args=[input.alert_data],
                start_to_close_timeout=timedelta(seconds=90),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=2),
                    maximum_attempts=2,
                ),
            )
            self._progress.plan_reasoning = "Generated dynamically by AI Planner based on alert context."
        else:
            # Static plan (deterministic, no IO)
            plan = self._build_plan(input.alert_data)
            self._progress.plan_reasoning = (
                "1) Triage first to understand severity and extract entities. "
                "2) Evidence collection and network discovery run in PARALLEL. "
                "3) Compression needs evidence data, so it waits. "
                "4) RCA needs both compressed evidence AND network context. "
                "5) Response planning depends on root cause identification."
            )

        self._progress.total_phases = len(plan)
        self._progress.phases = [
            {
                "phase_num": i + 1,
                "parallel": len(phase) > 1,
                "agents": [t["agent"] for t in phase],
                "status": "pending",
            }
            for i, phase in enumerate(plan)
        ]
        self._progress.status = "running"

        # ---- EXECUTION ----
        all_reports: Dict[str, Dict[str, Any]] = {}

        # Retry policy for all activities
        retry_policy = RetryPolicy(
            initial_interval=timedelta(seconds=1),
            backoff_coefficient=2.0,
            maximum_attempts=3,
            maximum_interval=timedelta(seconds=30),
        )

        if input.use_ai_planner:
            # ---- DYNAMIC EXECUTION (AI Planner path) ----
            # Generic loop over however many phases the AI planned
            for phase_idx, phase in enumerate(plan):
                self._progress.current_phase = phase_idx + 1
                self._progress.phases[phase_idx]["status"] = "running"

                results = await asyncio.gather(
                    *[
                        workflow.execute_activity(
                            td["activity"],
                            args=[context_dict],
                            start_to_close_timeout=timedelta(seconds=60),
                            retry_policy=retry_policy,
                        )
                        for td in phase
                    ]
                )
                for td, res in zip(phase, results):
                    context_dict = res["context"]
                    all_reports[td["id"]] = res["report"]
                    self._progress.completed_reports[td["id"]] = res["report"]
                self._progress.phases[phase_idx]["status"] = "completed"

        else:
            # ---- STATIC EXECUTION (Legacy adaptive loop) ----
            # Phase 1: Triage
            phase_idx = 0
            self._progress.current_phase = 1
            self._progress.phases[phase_idx]["status"] = "running"
            task_def = plan[phase_idx][0]
            result = await workflow.execute_activity(
                task_def["activity"],
                args=[context_dict],
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=retry_policy,
            )
            context_dict = result["context"]
            all_reports[task_def["id"]] = result["report"]
            self._progress.completed_reports[task_def["id"]] = result["report"]
            self._progress.phases[phase_idx]["status"] = "completed"

            # Adaptive Loop for Phases 2, 3, 4
            looping = True
            while looping:
                ctx_obj = InvestigationContext.from_dict(context_dict)
                ctx_obj.confidence_history.append(ctx_obj.rca_findings.get("confidence_score", 0.0))
                context_dict = ctx_obj.to_dict()

                # Phase 2: Evidence + Discovery
                phase_idx = 1
                self._progress.current_phase = 2
                self._progress.phases[phase_idx]["status"] = "running"
                
                results = await asyncio.gather(
                    *[
                        workflow.execute_activity(
                            td["activity"],
                            args=[context_dict],
                            start_to_close_timeout=timedelta(seconds=60),
                            retry_policy=retry_policy,
                        )
                        for td in plan[phase_idx]
                    ]
                )
                for td, res in zip(plan[phase_idx], results):
                    if td["id"] == "task-evidence":
                        context_dict = res["context"]
                    all_reports[td["id"]] = res["report"]
                    self._progress.completed_reports[td["id"]] = res["report"]
                self._progress.phases[phase_idx]["status"] = "completed"

                # Phase 3: Compression
                phase_idx = 2
                self._progress.current_phase = 3
                self._progress.phases[phase_idx]["status"] = "running"
                task_def = plan[phase_idx][0]
                result = await workflow.execute_activity(
                    task_def["activity"],
                    args=[context_dict],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=retry_policy,
                )
                context_dict = result["context"]
                all_reports[task_def["id"]] = result["report"]
                self._progress.completed_reports[task_def["id"]] = result["report"]
                self._progress.phases[phase_idx]["status"] = "completed"

                # Phase 4: RCA
                phase_idx = 3
                self._progress.current_phase = 4
                self._progress.phases[phase_idx]["status"] = "running"
                task_def = plan[phase_idx][0]
                result = await workflow.execute_activity(
                    task_def["activity"],
                    args=[context_dict],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=retry_policy,
                )
                context_dict = result["context"]
                all_reports[task_def["id"]] = result["report"]
                self._progress.completed_reports[task_def["id"]] = result["report"]
                self._progress.phases[phase_idx]["status"] = "completed"

                # Adaptive Loop Check
                ctx_obj = InvestigationContext.from_dict(context_dict)
                self._progress.iteration = ctx_obj.iteration
                self._progress.confidence_history = ctx_obj.confidence_history
                self._progress.messages = [m.to_dict() for m in ctx_obj.messages]
                
                if ctx_obj.needs_reinvestigation():
                    ctx_obj.iteration += 1
                    self._progress.iteration = ctx_obj.iteration
                    context_dict = ctx_obj.to_dict()
                else:
                    looping = False

            # Phase 5: Response
            phase_idx = 4
            self._progress.current_phase = 5
            self._progress.phases[phase_idx]["status"] = "running"
            task_def = plan[phase_idx][0]
            result = await workflow.execute_activity(
                task_def["activity"],
                args=[context_dict],
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=retry_policy,
            )
            context_dict = result["context"]
            all_reports[task_def["id"]] = result["report"]
            self._progress.completed_reports[task_def["id"]] = result["report"]
            self._progress.phases[phase_idx]["status"] = "completed"

        # ---- SYNTHESIS ----
        synthesis = self._synthesize(all_reports, InvestigationContext.from_dict(context_dict))

        total_duration_ms = int(
            (workflow.now() - run_start).total_seconds() * 1000
        )
        
        self._progress.synthesis = synthesis

        # ---- APPROVAL GATE ----
        response_report = all_reports.get("task-response", {})
        actions_recommended = response_report.get("findings", {}).get("actions_recommended", [])
        
        if actions_recommended:
            self._progress.status = "pending_approval"
            await workflow.wait_condition(lambda: self._approval_decision is not None)
            
            if self._approval_decision == "approve":
                self._progress.status = "executing_response"
                try:
                    await workflow.execute_activity(
                        "execute_response_activity",
                        args=[self._progress.run_id, response_report],
                        start_to_close_timeout=timedelta(seconds=60),
                    )
                except Exception as e:
                    workflow.logger.error(f"Failed to execute response: {e}")
                    
        self._progress.status = "completed"
        self._progress.completed_at = workflow.now().isoformat()
        self._progress.total_duration_ms = total_duration_ms
        
        try:
            await workflow.execute_activity(
                persist_investigation_results_activity,
                args=[asdict(self._progress)],
                start_to_close_timeout=timedelta(seconds=30),
            )
        except Exception as e:
            workflow.logger.error(f"Failed to persist investigation results: {e}")

        return {
            "run_id": run_id,
            "status": "completed",
            "total_duration_ms": total_duration_ms,
            "synthesis": synthesis,
            "reports": all_reports,
        }

    # ----------------------------------------------------------------
    # Internal helpers (deterministic, no IO — safe inside workflow)
    # ----------------------------------------------------------------

    def _build_plan(self, alert_data: Dict[str, Any]) -> List[List[Dict]]:
        """Build the phased execution plan (mirrors OrchestratorAgent.plan)."""
        return [
            # Phase 1: Triage (serial)
            [
                {
                    "id": "task-triage",
                    "agent": "triage_agent",
                    "activity": "triage_activity",
                    "description": "Analyze alert severity, classify threat, identify entities",
                }
            ],
            # Phase 2: Evidence + Discovery (parallel)
            [
                {
                    "id": "task-evidence",
                    "agent": "evidence_agent",
                    "activity": "evidence_activity",
                    "description": "Expand entity graph and collect evidence",
                },
                {
                    "id": "task-discovery",
                    "agent": "discovery_agent",
                    "activity": "discovery_activity",
                    "description": "Probe network reachability and open ports",
                },
            ],
            # Phase 3: Compression (serial)
            [
                {
                    "id": "task-compression",
                    "agent": "compression_agent",
                    "activity": "compression_activity",
                    "description": "7-stage event noise reduction pipeline",
                }
            ],
            # Phase 4: RCA (serial, depends on compression + discovery)
            [
                {
                    "id": "task-rca",
                    "agent": "rca_agent",
                    "activity": "rca_activity",
                    "description": "Root cause analysis and attack chain reconstruction",
                }
            ],
            # Phase 5: Response (serial)
            [
                {
                    "id": "task-response",
                    "agent": "response_agent",
                    "activity": "response_activity",
                    "description": "Generate prioritised response plan",
                }
            ],
        ]

    def _synthesize(self, reports: Dict[str, Dict[str, Any]], context: Any) -> Dict[str, Any]:
        """Synthesise all agent reports into a final verdict."""
        triage = reports.get("task-triage", {}).get("findings", {})
        evidence = reports.get("task-evidence", {}).get("findings", {})
        compression = reports.get("task-compression", {}).get("findings", {})
        rca = reports.get("task-rca", {}).get("findings", {})
        response = reports.get("task-response", {}).get("findings", {})

        severity = triage.get("severity", "Unknown")
        root_cause = rca.get("root_cause", "Undetermined")
        confidence = rca.get("confidence_score", 0)
        recommended_actions = response.get("actions_recommended", [])
        total_actions = len(recommended_actions)
        compression_ratio = compression.get("compression_ratio", "N/A")
        blast_radius = rca.get("blast_radius", 0)

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
            "all_succeeded": all(
                r.get("status") == "completed" for r in reports.values()
            ),
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
