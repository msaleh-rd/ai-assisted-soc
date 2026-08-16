"""Orchestrator API — SSE-streaming agentic investigation endpoint."""

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional

from backend.services.orchestrator import OrchestratorAgent

router = APIRouter(prefix="/api/v3/orchestrator", tags=["Orchestrator - Agentic Investigation"])

orchestrator = OrchestratorAgent()


class OrchestrationRequest(BaseModel):
    """Request to run a full agentic investigation."""
    task: str = "Investigate security alert"
    alert_data: Dict[str, Any]


@router.post("/investigate")
async def investigate_stream(request: OrchestrationRequest):
    """
    Run a full agentic investigation with SSE streaming.

    The orchestrator:
    1. Plans sub-tasks from the alert
    2. Delegates to specialized agents (some in parallel)
    3. Streams progress events as each agent starts/completes
    4. Synthesizes final findings

    Returns: text/event-stream with events:
    - run_start, plan_created, phase_start, agent_start,
      agent_complete, phase_complete, synthesis_start, run_complete
    """
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
        "orchestration_pattern": "plan-delegate-synthesize",
        "supports_parallel": True,
    }
