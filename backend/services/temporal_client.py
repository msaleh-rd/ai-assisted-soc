"""Temporal Client helper — used by the FastAPI API layer to start and query workflows.

Provides a cached async client and convenience methods for the orchestrator routes.
"""

import os
import uuid
import logging
from typing import Any, Dict, List, Optional

from temporalio.client import Client, WorkflowHandle, WorkflowExecutionStatus

from backend.services.temporal_workflows import InvestigationInput, InvestigationWorkflow

TEMPORAL_HOST = os.getenv("TEMPORAL_HOST", "localhost:7233")
TEMPORAL_NAMESPACE = os.getenv("TEMPORAL_NAMESPACE", "default")
TASK_QUEUE = "soc-investigation-queue"

logger = logging.getLogger("temporal-client")

# Module-level cached client
_client: Optional[Client] = None


async def get_client() -> Client:
    """Return a cached Temporal client (creates one on first call)."""
    global _client
    if _client is None:
        _client = await Client.connect(TEMPORAL_HOST, namespace=TEMPORAL_NAMESPACE)
        logger.info("Connected to Temporal at %s", TEMPORAL_HOST)
    return _client


async def start_investigation(
    task: str,
    alert_data: Dict[str, Any],
    workflow_id: Optional[str] = None,
) -> str:
    """
    Start a new InvestigationWorkflow.

    Returns the workflow_id that can be used to query progress or fetch results.
    """
    client = await get_client()

    if workflow_id is None:
        workflow_id = f"soc-investigation-{uuid.uuid4().hex[:12]}"

    input_data = InvestigationInput(task=task, alert_data=alert_data)

    handle = await client.start_workflow(
        InvestigationWorkflow.run,
        input_data,
        id=workflow_id,
        task_queue=TASK_QUEUE,
    )

    logger.info("Started investigation workflow: %s", workflow_id)
    return workflow_id


async def get_investigation_status(workflow_id: str) -> Dict[str, Any]:
    """
    Query a running workflow for its current progress.

    Returns the InvestigationProgress dict including current phase,
    completed reports, etc.
    """
    client = await get_client()
    handle = client.get_workflow_handle(workflow_id)

    try:
        progress = await handle.query(InvestigationWorkflow.get_progress)
        return progress
    except Exception as e:
        logger.warning("Failed to query workflow %s: %s", workflow_id, e)
        # If the workflow completed, try to get the result instead
        try:
            result = await handle.result()
            return {
                "run_id": result.get("run_id", ""),
                "status": "completed",
                "synthesis": result.get("synthesis"),
                "total_duration_ms": result.get("total_duration_ms", 0),
            }
        except Exception:
            return {"status": "unknown", "error": str(e)}


async def get_investigation_result(workflow_id: str) -> Dict[str, Any]:
    """
    Wait for and return the final result of a completed investigation workflow.

    This blocks until the workflow completes if it is still running.
    """
    client = await get_client()
    handle = client.get_workflow_handle(workflow_id)
    result = await handle.result()
    return result


async def list_investigations(limit: int = 20) -> List[Dict[str, Any]]:
    """
    List recent investigation workflows from Temporal.

    Returns basic metadata for each workflow execution.
    """
    client = await get_client()
    investigations = []

    async for workflow_exec in client.list_workflows(
        query=f'WorkflowType = "InvestigationWorkflow"',
        limit=limit,
    ):
        status_map = {
            WorkflowExecutionStatus.RUNNING: "running",
            WorkflowExecutionStatus.COMPLETED: "completed",
            WorkflowExecutionStatus.FAILED: "failed",
            WorkflowExecutionStatus.CANCELED: "canceled",
            WorkflowExecutionStatus.TERMINATED: "terminated",
            WorkflowExecutionStatus.TIMED_OUT: "timed_out",
        }
        investigations.append({
            "workflow_id": workflow_exec.id,
            "run_id": workflow_exec.run_id,
            "status": status_map.get(workflow_exec.status, "unknown"),
            "start_time": workflow_exec.start_time.isoformat() if workflow_exec.start_time else None,
            "close_time": workflow_exec.close_time.isoformat() if workflow_exec.close_time else None,
        })

    return investigations


async def cancel_investigation(workflow_id: str) -> bool:
    """Cancel a running investigation workflow."""
    client = await get_client()
    handle = client.get_workflow_handle(workflow_id)
    try:
        await handle.cancel()
        logger.info("Cancelled workflow: %s", workflow_id)
        return True
    except Exception as e:
        logger.warning("Failed to cancel workflow %s: %s", workflow_id, e)
        return False
