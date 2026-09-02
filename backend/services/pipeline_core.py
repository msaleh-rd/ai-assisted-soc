"""Pipeline Core — single source of truth for shared orchestration logic.

This module contains pure functions with NO framework dependencies (no Temporal,
no SSE, no FastAPI).  Both the in-memory OrchestratorAgent and the Temporal
InvestigationWorkflow delegate to the functions defined here so that plan
definitions, synthesis logic, and AI-planner invocation are never duplicated.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

_log = logging.getLogger("pipeline-core")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STATIC_PLAN_REASONING = (
    "1) Triage first to understand severity and extract entities. "
    "2) Evidence collection and network discovery can run in PARALLEL since they're independent. "
    "3) Compression needs evidence data, so it waits. "
    "4) RCA needs both compressed evidence AND network context. "
    "5) Response planning depends on root cause identification."
)

# Maps agent names → Temporal activity names (used by Temporal pathway)
AGENT_TO_ACTIVITY = {
    "triage_agent": "triage_activity",
    "evidence_agent": "evidence_activity",
    "discovery_agent": "discovery_activity",
    "compression_agent": "compression_activity",
    "rca_agent": "rca_activity",
    "response_agent": "response_activity",
}

# Canonical task definitions — the single source of truth for the 5-phase plan.
# Each entry: (task_id, agent_name, description, [depends_on])
STATIC_TASK_DEFS = [
    # Phase 1: Triage (serial)
    [
        ("task-triage", "triage_agent",
         "Analyze alert severity, classify threat, identify entities", []),
    ],
    # Phase 2: Evidence + Discovery (parallel)
    [
        ("task-evidence", "evidence_agent",
         "Expand entity graph and collect evidence from data sources", ["task-triage"]),
        ("task-discovery", "discovery_agent",
         "Probe network reachability and open ports for IP entities", ["task-triage"]),
    ],
    # Phase 3: Compression (serial)
    [
        ("task-compression", "compression_agent",
         "Compress events through 7-stage noise reduction pipeline", ["task-evidence"]),
    ],
    # Phase 4: RCA (serial)
    [
        ("task-rca", "rca_agent",
         "Analyze root cause, reconstruct attack chain, score confidence",
         ["task-compression", "task-discovery"]),
    ],
    # Phase 5: Response (serial)
    [
        ("task-response", "response_agent",
         "Generate prioritized response plan based on RCA findings", ["task-rca"]),
    ],
]


# ---------------------------------------------------------------------------
# Plan Builders
# ---------------------------------------------------------------------------

def build_static_plan_dicts() -> List[List[Dict[str, Any]]]:
    """Return the static 5-phase plan as plain dicts (for Temporal pathway).

    Each task dict contains: id, agent, activity, description.
    """
    plan = []
    for phase_defs in STATIC_TASK_DEFS:
        phase = []
        for task_id, agent_name, description, _deps in phase_defs:
            phase.append({
                "id": task_id,
                "agent": agent_name,
                "activity": AGENT_TO_ACTIVITY[agent_name],
                "description": description,
            })
        plan.append(phase)
    return plan


def build_static_plan_subtasks():
    """Return the static 5-phase plan as SubTask objects (for in-memory pathway).

    Imports SubTask / ExecutionPlan lazily to avoid circular deps.
    """
    from backend.services.orchestrator import SubTask, ExecutionPlan

    plan_id = f"plan-{uuid.uuid4().hex[:8]}"
    phases = []
    for phase_defs in STATIC_TASK_DEFS:
        phase = []
        for task_id, agent_name, description, depends_on in phase_defs:
            phase.append(SubTask(
                id=task_id,
                agent_name=agent_name,
                description=description,
                depends_on=list(depends_on),
            ))
        phases.append(phase)

    return ExecutionPlan(
        plan_id=plan_id,
        objective="Investigate security alert and recommend response",
        phases=phases,
        reasoning=STATIC_PLAN_REASONING,
    )


async def build_ai_plan(alert_data: Dict[str, Any], valid_agents: set):
    """Call the LLM AI planner and return an ExecutionPlan.

    Falls back to the static plan on failure.

    Args:
        alert_data: The raw alert dict.
        valid_agents: Set of registered agent names for validation.

    Returns:
        An ExecutionPlan (SubTask-based).
    """
    from backend.services.orchestrator import SubTask, ExecutionPlan

    plan_id = f"plan-{uuid.uuid4().hex[:8]}"

    try:
        from backend.services.llm_client import get_llm, PlannerOutput
        from backend.services.prompt_manager import prompt_manager
        import json

        llm = get_llm(role="planner")
        structured_llm = llm.with_structured_output(PlannerOutput)
        system_prompt = prompt_manager.get_system_prompt("planner")
        user_prompt = prompt_manager.build_user_prompt(
            "planner", alert_json=json.dumps(alert_data, indent=2)
        )

        result = await structured_llm.ainvoke(f"{system_prompt}\n\n{user_prompt}")

        # Validate: every agent_name must exist in the registry
        phases = []
        for phase_tasks in result.phases:
            phase = []
            for t in phase_tasks:
                if t.agent_name not in valid_agents:
                    _log.warning(
                        "AI Planner referenced unknown agent '%s' — skipping",
                        t.agent_name,
                    )
                    continue
                phase.append(SubTask(
                    id=t.id,
                    agent_name=t.agent_name,
                    description=t.description,
                ))
            if phase:
                phases.append(phase)

        if phases:
            _log.info(
                "AI Planner generated %d phases with %d total tasks",
                len(phases),
                sum(len(p) for p in phases),
            )
            return ExecutionPlan(
                plan_id=plan_id,
                objective="Investigate security alert and recommend response",
                phases=phases,
                reasoning=result.reasoning,
            )
        else:
            _log.warning("AI Planner produced an empty plan — falling back to static")

    except Exception as e:
        _log.error("AI Planner failed, falling back to static plan: %s", e)

    return build_static_plan_subtasks()


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------

def _get_findings(report, key: str, default=None):
    """Extract a value from report findings, handling both AgentReport objects
    and plain dicts (Temporal payloads)."""
    if report is None:
        return default

    # AgentReport object (in-memory orchestrator)
    if hasattr(report, "findings"):
        return report.findings.get(key, default)

    # Plain dict (Temporal workflow)
    if isinstance(report, dict):
        return report.get("findings", {}).get(key, default)

    return default


def _get_report_status(report) -> str:
    """Get the status string from a report, handling both objects and dicts."""
    if report is None:
        return "unknown"
    if hasattr(report, "status"):
        # AgentReport.status is an Enum
        s = report.status
        return s.value if hasattr(s, "value") else str(s)
    if isinstance(report, dict):
        return report.get("status", "unknown")
    return "unknown"


def find_matching_playbook(alert_data: Dict[str, Any]) -> Optional[Any]:
    """Wave 3, Phase K: returns the first declarative playbook (see
    `backend/services/playbook_engine.py`) whose trigger matches this alert, or
    None if no playbook applies -- in which case callers fall through to the
    static 5-phase plan unchanged (zero regression for the common/no-match
    case, which is virtually every alert today since only one starter
    playbook exists)."""
    from backend.services.playbook_engine import playbook_engine
    return playbook_engine.find_matching_playbook(alert_data)


def synthesize_reports(
    reports: Dict[str, Any],
    context: Any = None,
) -> Dict[str, Any]:
    """Synthesise all agent reports into a final investigation verdict.

    Works with both AgentReport objects (in-memory) and plain dicts (Temporal).

    Args:
        reports: Mapping of task-id → AgentReport or dict.
        context: InvestigationContext (optional, for iteration/message data).

    Returns:
        Synthesis dict with verdict, executive_summary, recommended_actions, etc.
    """
    triage = reports.get("task-triage")
    compression = reports.get("task-compression")
    rca = reports.get("task-rca")
    response = reports.get("task-response")

    severity = _get_findings(triage, "severity", "Unknown")
    root_cause = _get_findings(rca, "root_cause", "Undetermined")
    confidence = _get_findings(rca, "confidence_score", 0)
    recommended_actions = _get_findings(response, "actions_recommended", [])
    total_actions = len(recommended_actions)
    compression_ratio = _get_findings(compression, "compression_ratio", "N/A")
    blast_radius = _get_findings(rca, "blast_radius", 0)

    # Determine overall verdict
    if confidence >= 0.8:
        verdict = "High-confidence root cause identified. Immediate response recommended."
    elif confidence >= 0.5:
        verdict = "Moderate confidence in findings. Consider additional investigation."
    else:
        verdict = "Low confidence. Adaptive re-investigation recommended."

    # Extract context metadata (safe for None context)
    if context is not None:
        messages = context.messages if hasattr(context, "messages") else []
        messages_exchanged = len([
            m.to_dict() if hasattr(m, "to_dict") else m for m in messages
        ])
        iteration = context.iteration if hasattr(context, "iteration") else 0
        confidence_history = (
            context.confidence_history
            if hasattr(context, "confidence_history")
            else []
        )
    else:
        messages_exchanged = 0
        iteration = 0
        confidence_history = []

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
            _get_report_status(r) == "completed" for r in reports.values()
        ),
        "iterations": iteration,
        "confidence_history": confidence_history,
        "messages_exchanged": messages_exchanged,
        "executive_summary": (
            f"Investigation complete. Severity: {severity}. "
            f"Root cause: {root_cause} (confidence: {confidence:.0%}). "
            f"Blast radius: {blast_radius} entities. "
            f"Event noise reduced by {compression_ratio}. "
            f"{total_actions} response actions recommended."
        ),
    }
