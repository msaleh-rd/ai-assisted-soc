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
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/v3/orchestrator", tags=["Orchestrator - Agentic Investigation"])

logger = logging.getLogger("orchestrator-api")

USE_TEMPORAL = os.getenv("USE_TEMPORAL", "false").lower() in ("true", "1", "yes")


# -----------------------------------------------------------------------
# Request / Response schemas
# -----------------------------------------------------------------------

class OrchestrationRequest(BaseModel):
    """Request to run a full agentic investigation."""
    task: str = "Investigate security alert"
    alert_data: Dict[str, Any]


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
            async for event in orchestrator.execute_stream(request.task, request.alert_data):
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

        while True:
            progress = await get_investigation_status(workflow_id)
            status = progress.get("status", "unknown")

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

            # Terminal state
            if status == "completed":
                yield _sse("run_complete", {
                    "workflow_id": workflow_id,
                    "status": "completed",
                    "synthesis": progress.get("synthesis"),
                    "total_duration_ms": progress.get("total_duration_ms", 0),
                })
                return
            elif status in ("failed", "unknown"):
                yield _sse("run_error", {
                    "workflow_id": workflow_id,
                    "status": status,
                    "error": progress.get("error", ""),
                })
                return

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
    List recent investigation workflows from Temporal.

    Only available in Temporal mode.
    """
    if not USE_TEMPORAL:
        raise HTTPException(
            status_code=400,
            detail="Temporal mode is not enabled. Set USE_TEMPORAL=true to use this endpoint.",
        )

    from backend.services.temporal_client import list_investigations as fetch_list
    investigations = await fetch_list(limit=50)
    return {"investigations": investigations, "count": len(investigations)}


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
