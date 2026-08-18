"""Orchestrator API — SSE-streaming agentic investigation endpoint.

Supports two modes:
- **Temporal mode** (USE_TEMPORAL=true): Durable workflow-based orchestration
  with full visibility via Temporal Web UI.
- **In-memory mode** (default / USE_TEMPORAL=false): Original asyncio-based
  orchestration with direct SSE streaming.
"""

import asyncio
import json
import os
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/v3/orchestrator", tags=["Orchestrator - Agentic Investigation"])

logger = logging.getLogger("orchestrator-api")

USE_TEMPORAL = os.getenv("USE_TEMPORAL", "false").lower() in ("true", "1", "yes")
IN_MEMORY_INVESTIGATIONS: List[Dict[str, Any]] = []


# -----------------------------------------------------------------------
# Request / Response schemas
# -----------------------------------------------------------------------

class OrchestrationRequest(BaseModel):
    """Request to run a full agentic investigation."""
    task: str = "Investigate security alert"
    alert_data: Dict[str, Any]
    use_ai_planner: bool = False


class InvestigationStartResponse(BaseModel):
    """Response when a Temporal investigation is started."""
    workflow_id: str
    status: str
    message: str
    temporal_ui_url: str


# -----------------------------------------------------------------------
# Temporal-backed endpoints
# -----------------------------------------------------------------------

@router.post("/investigate")
async def investigate(request: OrchestrationRequest):
    """
    Run a full agentic investigation.

    - **Temporal mode**: Starts a durable workflow and returns the workflow_id.
    - **In-memory mode**: Streams SSE events directly.
    """
    if USE_TEMPORAL:
        from backend.services.temporal_client import start_investigation
        workflow_id = await start_investigation(
            task=request.task,
            alert_data=request.alert_data,
            use_ai_planner=request.use_ai_planner,
        )
        return InvestigationStartResponse(
            workflow_id=workflow_id,
            status="started",
            message="Investigation workflow started. Query progress or view in Temporal UI.",
            temporal_ui_url=f"http://localhost:8080/namespaces/default/workflows/{workflow_id}",
        )
    else:
        # Original in-memory SSE streaming mode
        from backend.services.orchestrator import OrchestratorAgent
        orchestrator = OrchestratorAgent()

        async def event_generator():
            inv_id = f"inv-{uuid.uuid4().hex[:8]}"
            investigation_record = {
                "workflow_id": inv_id,
                "task": request.task,
                "status": "running",
                "started_at": datetime.utcnow().isoformat(),
                "synthesis": None,
                "total_duration_ms": 0
            }
            
            async for event in orchestrator.execute_stream(
                request.task, request.alert_data, use_ai_planner=request.use_ai_planner
            ):
                # We need to peek inside the SSE string to see if the run completed
                try:
                    lines = event.strip().split('\n')
                    is_complete = False
                    for line in lines:
                        if line == "event: run_complete":
                            is_complete = True
                        elif is_complete and line.startswith("data: "):
                            data = json.loads(line[6:])
                            investigation_record["status"] = "completed"
                            investigation_record["synthesis"] = data.get("synthesis")
                            investigation_record["total_duration_ms"] = data.get("total_duration_ms", 0)
                            investigation_record["completed_at"] = datetime.utcnow().isoformat()
                            IN_MEMORY_INVESTIGATIONS.insert(0, investigation_record) # Insert at beginning
                            break
                except Exception:
                    pass
                    
                yield event

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )


@router.get("/investigate/{workflow_id}")
async def get_investigation_progress(workflow_id: str):
    """
    Query the progress of a running Temporal investigation.

    Returns the current phase, completed agent reports, and partial results.
    Only available in Temporal mode.
    """
    if not USE_TEMPORAL:
        raise HTTPException(
            status_code=400,
            detail="Temporal mode is not enabled. Set USE_TEMPORAL=true to use this endpoint.",
        )

    from backend.services.temporal_client import get_investigation_status
    progress = await get_investigation_status(workflow_id)
    return progress


@router.get("/investigate/{workflow_id}/result")
async def get_investigation_result(workflow_id: str):
    """
    Get the final result of a completed investigation workflow.

    Blocks until the workflow completes if still running.
    Only available in Temporal mode.
    """
    if not USE_TEMPORAL:
        raise HTTPException(
            status_code=400,
            detail="Temporal mode is not enabled. Set USE_TEMPORAL=true to use this endpoint.",
        )

    from backend.services.temporal_client import get_investigation_result as fetch_result
    try:
        result = await fetch_result(workflow_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigate/{workflow_id}/stream")
async def stream_investigation(workflow_id: str):
    """
    SSE stream that polls a Temporal workflow and emits progress events.

    Preserves the frontend SSE experience while using Temporal under the hood.
    Only available in Temporal mode.
    """
    if not USE_TEMPORAL:
        raise HTTPException(
            status_code=400,
            detail="Temporal mode is not enabled. Set USE_TEMPORAL=true to use this endpoint.",
        )

    from backend.services.temporal_client import get_investigation_status

    async def sse_poll():
        last_phase = 0
        last_reports = set()
        last_iteration = 0
        last_status = "unknown"

        while True:
            progress = await get_investigation_status(workflow_id)
            status = progress.get("status", "unknown")

            # Emit plan_created when transitioning from planning to running,
            # or if we missed the transition (connected after it started running)
            if status != "planning" and last_status in ["unknown", "planning"]:
                yield _sse("plan_created", {
                    "workflow_id": workflow_id,
                    "reasoning": progress.get("plan_reasoning", ""),
                    "total_phases": progress.get("total_phases", 0),
                    "total_tasks": sum(len(p.get("agents", [])) for p in progress.get("phases", [])),
                    "phases": progress.get("phases", []),
                })
            last_status = status

            current_phase = progress.get("current_phase", 0)
            completed_reports = progress.get("completed_reports", {})

            # Emit events for new phase transitions
            if current_phase > last_phase:
                phase_info = {}
                phases = progress.get("phases", [])
                if current_phase <= len(phases):
                    phase_info = phases[current_phase - 1]
                yield _sse("phase_start", {
                    "workflow_id": workflow_id,
                    "phase_num": current_phase,
                    "parallel": phase_info.get("parallel", False),
                    "agents": phase_info.get("agents", []),
                })
                last_phase = current_phase
                
            iteration = progress.get("iteration", 0)
            if iteration > last_iteration:
                confidence_history = progress.get("confidence_history", [])
                last_confidence = confidence_history[-1] if confidence_history else 0.0
                yield _sse("adaptive_loop_start", {
                    "workflow_id": workflow_id,
                    "iteration": iteration,
                    "confidence": last_confidence,
                    "reason": "Re-investigating based on findings",
                })
                last_iteration = iteration

            # Emit events for newly completed agent reports
            for task_id, report in completed_reports.items():
                if task_id not in last_reports:
                    yield _sse("agent_complete", {
                        "workflow_id": workflow_id,
                        "task_id": task_id,
                        "agent_name": report.get("agent_name", ""),
                        "report": report,
                    })
                    last_reports.add(task_id)

            # Wait for approval state
            if status == "pending_approval" and "pending_approval" not in last_reports:
                yield _sse("pending_approval", {
                    "workflow_id": workflow_id,
                    "status": "pending_approval"
                })
                last_reports.add("pending_approval")
                
            # Terminal state
            if status == "completed":
                yield _sse("run_complete", {
                    "workflow_id": workflow_id,
                    "status": "completed",
                    "synthesis": progress.get("synthesis"),
                    "total_duration_ms": progress.get("total_duration_ms", 0),
                })
                return
            elif status == "failed":
                yield _sse("run_error", {
                    "workflow_id": workflow_id,
                    "status": status,
                    "error": progress.get("error", ""),
                })
                return
            elif status == "unknown":
                # Workflow query timed out (e.g. event loop blocked), just wait and retry
                await asyncio.sleep(1.0)
                continue

            await asyncio.sleep(0.5)

    return StreamingResponse(
        sse_poll(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/investigations")
async def list_investigations():
    """
    List recent investigation workflows.

    Works in both Temporal mode and in-memory mode.
    """
    if not USE_TEMPORAL:
        return {"investigations": IN_MEMORY_INVESTIGATIONS, "count": len(IN_MEMORY_INVESTIGATIONS)}

    from backend.services.temporal_client import list_investigations as fetch_list
    investigations = await fetch_list(limit=50)
    return {"investigations": investigations, "count": len(investigations)}

@router.get("/approvals/pending")
async def list_pending_approvals():
    """
    List all investigations that are currently waiting for human approval.
    """
    if not USE_TEMPORAL:
        return {"pending_approvals": []}
        
    try:
        from temporalio.client import Client
        import os
        from backend.services.temporal_client import get_investigation_status
        temporal_host = os.getenv("TEMPORAL_HOST", "127.0.0.1:7233")
        client = await Client.connect(temporal_host)
        
        pending = []
        async for workflow_exec in client.list_workflows(
            query='WorkflowType = "InvestigationWorkflow" and ExecutionStatus = "Running"',
            limit=50,
        ):
            progress = await get_investigation_status(workflow_exec.id)
            if progress.get("status") == "pending_approval":
                reports = progress.get("completed_reports", {})
                
                # Get recommended actions from Response agent
                response_report = reports.get("task-response", {})
                actions = response_report.get("findings", {}).get("actions_recommended", [])
                
                # Get entities from Triage agent
                triage_report = reports.get("task-triage", {})
                entities = triage_report.get("findings", {}).get("entities_identified", [])
                
                synthesis = progress.get("synthesis", {})
                
                pending.append({
                    "workflow_id": workflow_exec.id,
                    "actions": actions,
                    "confidence": response_report.get("findings", {}).get("confidence", 0.90),
                    "entities": entities,
                    "summary": synthesis.get("executive_summary", "Approval required for response actions.")
                })
                
        return {"pending_approvals": pending}
    except Exception as e:
        logger.error(f"Failed to list pending approvals: {e}")
        return {"pending_approvals": []}


from pydantic import BaseModel
class ApprovalDecision(BaseModel):
    decision: str
    comment: str = ""

@router.post("/investigate/{workflow_id}/approve")
async def approve_response(workflow_id: str, decision: ApprovalDecision):
    """
    Approve or reject a response plan that is pending approval.
    """
    if not USE_TEMPORAL:
        raise HTTPException(status_code=400, detail="Only supported in Temporal mode")
        
    try:
        from temporalio.client import Client
        import os
        temporal_host = os.getenv("TEMPORAL_HOST", "127.0.0.1:7233")
        client = await Client.connect(temporal_host)
        handle = client.get_workflow_handle(workflow_id)
        
        await handle.signal("approve_response", args=[decision.decision, decision.comment])
        
        return {"status": "success", "message": f"Signal {decision.decision} sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/investigate/{workflow_id}")
async def cancel_investigation(workflow_id: str):
    """
    Cancel a running investigation workflow.

    Only available in Temporal mode.
    """
    if not USE_TEMPORAL:
        raise HTTPException(
            status_code=400,
            detail="Temporal mode is not enabled. Set USE_TEMPORAL=true to use this endpoint.",
        )

    from backend.services.temporal_client import cancel_investigation as do_cancel
    success = await do_cancel(workflow_id)
    if success:
        return {"status": "cancelled", "workflow_id": workflow_id}
    raise HTTPException(status_code=500, detail="Failed to cancel workflow")


# -----------------------------------------------------------------------
# Common endpoints (work in both modes)
# -----------------------------------------------------------------------

@router.get("/agents")
async def list_agents():
    """List all available sub-agents and their capabilities."""
    from backend.services.orchestrator import AGENT_REGISTRY
    return {
        "agents": [
            {
                "name": agent.name,
                "description": agent.description,
            }
            for agent in AGENT_REGISTRY.values()
        ],
        "orchestration_mode": "temporal" if USE_TEMPORAL else "in-memory",
        "orchestration_pattern": "plan-delegate-synthesize",
        "supports_parallel": True,
    }


@router.get("/mode")
async def get_mode():
    """Return the current orchestration mode."""
    return {
        "mode": "temporal" if USE_TEMPORAL else "in-memory",
        "temporal_enabled": USE_TEMPORAL,
        "temporal_host": os.getenv("TEMPORAL_HOST", "localhost:7233") if USE_TEMPORAL else None,
        "task_queue": "soc-investigation-queue" if USE_TEMPORAL else None,
    }


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _sse(event_type: str, data: Any) -> str:
    """Format a Server-Sent Event string."""
    payload = json.dumps(data, default=str)
    return f"event: {event_type}\ndata: {payload}\n\n"
