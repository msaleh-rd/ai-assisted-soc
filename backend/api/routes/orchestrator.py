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
                "reports": {},
                "alert_data": request.alert_data,
                "total_duration_ms": 0
            }
            
            async for event in orchestrator.execute_stream(
                request.task, request.alert_data, use_ai_planner=request.use_ai_planner
            ):
                # Peek inside the SSE string to record completed agents and final synthesis
                try:
                    lines = event.strip().split('\n')
                    if len(lines) >= 2 and lines[1].startswith("data: "):
                        evt_type = lines[0].replace("event: ", "").strip()
                        data_payload = json.loads(lines[1][6:])
                        
                        if evt_type == "agent_complete":
                            task_id = data_payload.get("task_id")
                            if task_id and "report" in data_payload:
                                investigation_record["reports"][task_id] = data_payload["report"]
                        elif evt_type == "run_complete":
                            investigation_record["status"] = "completed"
                            investigation_record["synthesis"] = data_payload.get("synthesis")
                            investigation_record["total_duration_ms"] = data_payload.get("total_duration_ms", 0)
                            investigation_record["completed_at"] = datetime.utcnow().isoformat()
                            IN_MEMORY_INVESTIGATIONS.insert(0, investigation_record)
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
        last_sup_step = 0

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

            # Emit events for newly added supervisor thoughts & assessments
            sup_history = progress.get("supervisor_history", [])
            while last_sup_step < len(sup_history):
                step = sup_history[last_sup_step]
                yield _sse("supervisor_thought", {
                    "workflow_id": workflow_id,
                    "iteration": step.get("iteration", last_sup_step) + 1,
                    "supervisor_assessment": step.get("supervisor_assessment", ""),
                    "thought": step.get("thought", ""),
                    "action": step.get("action", ""),
                    "target_entities": step.get("target_entities", []),
                    "target_skills": step.get("target_skills", []),
                    "specific_goal": step.get("specific_goal", ""),
                    "pivot_entity_detected": step.get("pivot_entity_detected"),
                    "timestamp": step.get("timestamp", datetime.utcnow().isoformat()),
                })
                last_sup_step += 1

            current_phase = progress.get("current_phase", 0)
            completed_reports = progress.get("completed_reports", {})

            # Emit events for new phase transitions
            if current_phase > last_phase:
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
async def list_investigations(
    q: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """
    List, search, and filter past and ongoing investigation workflows.
    Aggregates data across Temporal, PostgreSQL, and In-Memory runs.
    """
    merged_map: Dict[str, Dict[str, Any]] = {}

    # 1. Fetch from PostgreSQL if available
    try:
        from backend.database.connection import get_db
        from backend.database.postgres import InvestigationRecord, RCAResultRecord, AuditRecord
        import contextlib

        with contextlib.closing(next(get_db())) as db:
            query = db.query(InvestigationRecord).order_by(InvestigationRecord.started_at.desc()).limit(100)
            records = query.all()
            for rec in records:
                rca = db.query(RCAResultRecord).filter(RCAResultRecord.investigation_id == rec.investigation_id).first()
                audit_count = db.query(AuditRecord).filter(AuditRecord.investigation_id == rec.investigation_id).count()
                
                duration = 0
                if rec.started_at and rec.completed_at:
                    duration = int((rec.completed_at - rec.started_at).total_seconds() * 1000)
                
                merged_map[rec.investigation_id] = {
                    "workflow_id": rec.investigation_id,
                    "status": rec.status or "completed",
                    "severity": rec.severity or ("Critical" if (rec.risk_score or 0) > 0.8 else "High" if (rec.risk_score or 0) > 0.5 else "Medium"),
                    "verdict": "Confirmed Incident" if (rec.risk_score or 0) > 0.6 else "Suspicious Activity",
                    "root_cause": rca.root_cause if rca else "Analysis completed",
                    "confidence": rca.confidence if rca else (rec.risk_score or 0.85),
                    "start_time": rec.started_at.isoformat() if rec.started_at else None,
                    "close_time": rec.completed_at.isoformat() if rec.completed_at else None,
                    "duration_ms": duration,
                    "entity_count": rec.entity_count or 0,
                    "actions_count": audit_count,
                    "source": "postgres"
                }
    except Exception as db_err:
        logger.debug(f"Postgres lookup skipped/unavailable: {db_err}")

    # 2. Fetch from In-Memory
    for inv in IN_MEMORY_INVESTIGATIONS:
        w_id = inv.get("workflow_id")
        if not w_id:
            continue
        synthesis = inv.get("synthesis") or {}
        merged_map[w_id] = {
            "workflow_id": w_id,
            "status": inv.get("status", "completed"),
            "severity": synthesis.get("severity") or "High",
            "verdict": synthesis.get("verdict") or "Security Alert",
            "root_cause": synthesis.get("root_cause") or synthesis.get("executive_summary") or inv.get("task", ""),
            "confidence": synthesis.get("confidence_score") or 0.85,
            "start_time": inv.get("started_at"),
            "close_time": inv.get("completed_at"),
            "duration_ms": inv.get("total_duration_ms", 0),
            "entity_count": len(synthesis.get("key_findings", [])),
            "actions_count": len(synthesis.get("recommended_immediate_actions", [])),
            "source": "in-memory"
        }

    # 3. Fetch from Temporal if enabled
    if USE_TEMPORAL:
        try:
            from backend.services.temporal_client import list_investigations as fetch_temporal, get_investigation_status
            temporal_invs = await fetch_temporal(limit=50)
            for t_inv in temporal_invs:
                w_id = t_inv["workflow_id"]
                existing = merged_map.get(w_id, {})
                
                # Enrich with progress details if status is running/pending
                status_val = t_inv.get("status", existing.get("status", "completed"))
                duration_val = existing.get("duration_ms", 0)
                root_cause_val = existing.get("root_cause", "")
                confidence_val = existing.get("confidence", 0.85)
                severity_val = existing.get("severity", "High")
                verdict_val = existing.get("verdict", "Investigation")
                actions_count = existing.get("actions_count", 0)
                
                try:
                    progress = await get_investigation_status(w_id)
                    status_val = progress.get("status", status_val)
                    if progress.get("total_duration_ms"):
                        duration_val = progress["total_duration_ms"]
                    synthesis = progress.get("synthesis") or {}
                    if synthesis:
                        root_cause_val = synthesis.get("executive_summary") or root_cause_val
                        confidence_val = synthesis.get("confidence_score") or confidence_val
                        verdict_val = synthesis.get("verdict") or verdict_val
                        actions_count = len(synthesis.get("recommended_immediate_actions", []))
                    
                    reports = progress.get("completed_reports", {})
                    triage = next((r for r in reports.values() if r.get("agent_name") == "triage_agent"), {})
                    if triage:
                        severity_val = triage.get("findings", {}).get("severity", severity_val)
                except Exception:
                    pass

                merged_map[w_id] = {
                    "workflow_id": w_id,
                    "status": status_val,
                    "severity": severity_val,
                    "verdict": verdict_val,
                    "root_cause": root_cause_val or "Automated Investigation",
                    "confidence": confidence_val,
                    "start_time": t_inv.get("start_time") or existing.get("start_time"),
                    "close_time": t_inv.get("close_time") or existing.get("close_time"),
                    "duration_ms": duration_val,
                    "entity_count": existing.get("entity_count", 0),
                    "actions_count": actions_count,
                    "source": "temporal"
                }
        except Exception as t_err:
            logger.debug(f"Temporal list error: {t_err}")

    # Convert map to list and sort by date descending
    investigation_list = list(merged_map.values())
    investigation_list.sort(key=lambda x: str(x.get("start_time") or ""), reverse=True)

    # 4. Apply Filters
    if q:
        query_str = q.lower().strip()
        investigation_list = [
            inv for inv in investigation_list
            if query_str in str(inv.get("workflow_id", "")).lower()
            or query_str in str(inv.get("root_cause", "")).lower()
            or query_str in str(inv.get("verdict", "")).lower()
            or query_str in str(inv.get("severity", "")).lower()
        ]

    if status and status.lower() != "all":
        investigation_list = [
            inv for inv in investigation_list
            if str(inv.get("status", "")).lower() == status.lower()
        ]

    if severity and severity.lower() != "all":
        investigation_list = [
            inv for inv in investigation_list
            if str(inv.get("severity", "")).lower() == severity.lower()
        ]

    total_count = len(investigation_list)
    paginated = investigation_list[offset : offset + limit]

    # Compute Summary Stats
    critical_count = sum(1 for inv in merged_map.values() if str(inv.get("severity", "")).lower() == "critical")
    avg_conf = (
        round(sum(float(inv.get("confidence", 0.8)) for inv in merged_map.values()) / max(len(merged_map), 1), 2)
        if merged_map else 0.0
    )
    total_actions = sum(int(inv.get("actions_count", 0)) for inv in merged_map.values())

    return {
        "investigations": paginated,
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "stats": {
            "total_count": len(merged_map),
            "critical_count": critical_count,
            "avg_confidence": avg_conf,
            "total_actions": total_actions,
        }
    }


@router.get("/investigations/{investigation_id}/details")
async def get_investigation_details(investigation_id: str):
    """
    Retrieve full drill-down data for an investigation.
    Includes synthesis, full agent reports, chain-of-thought reasoning,
    entity/attack graph, attack phases, blackboard messages, and audit trail.
    """
    detail: Dict[str, Any] = {
        "investigation_id": investigation_id,
        "workflow_id": investigation_id,
        "status": "completed",
        "severity": "High",
        "started_at": None,
        "completed_at": None,
        "duration_ms": 0,
        "synthesis": {},
        "reports": {},
        "attack_graph": {"nodes": [], "edges": []},
        "attack_phases": [],
        "chain_of_thought": "",
        "blackboard_messages": [],
        "audit_trail": [],
        "actions_recommended": [],
    }

    # 1. Try Temporal Query for live/rich workflow data
    if USE_TEMPORAL:
        try:
            from backend.services.temporal_client import get_investigation_status, get_investigation_result
            progress = await get_investigation_status(investigation_id)
            if progress:
                detail["status"] = progress.get("status", "completed")
                detail["started_at"] = progress.get("started_at")
                detail["completed_at"] = progress.get("completed_at")
                detail["duration_ms"] = progress.get("total_duration_ms", 0)
                detail["synthesis"] = progress.get("synthesis") or {}
                detail["reports"] = progress.get("completed_reports") or {}
                detail["blackboard_messages"] = progress.get("messages") or []
        except Exception as t_err:
            logger.debug(f"Temporal detail query error: {t_err}")

    # 2. Try Postgres query to fill or augment
    try:
        from backend.database.connection import get_db
        from backend.database.postgres import InvestigationRecord, RCAResultRecord, AuditRecord, AlertRecord
        import contextlib

        with contextlib.closing(next(get_db())) as db:
            rec = db.query(InvestigationRecord).filter(InvestigationRecord.investigation_id == investigation_id).first()
            if rec:
                detail["status"] = rec.status or detail["status"]
                detail["severity"] = rec.severity or detail["severity"]
                if rec.started_at and not detail["started_at"]:
                    detail["started_at"] = rec.started_at.isoformat()
                if rec.completed_at and not detail["completed_at"]:
                    detail["completed_at"] = rec.completed_at.isoformat()
                if rec.started_at and rec.completed_at and not detail["duration_ms"]:
                    detail["duration_ms"] = int((rec.completed_at - rec.started_at).total_seconds() * 1000)

            rca = db.query(RCAResultRecord).filter(RCAResultRecord.investigation_id == investigation_id).first()
            if rca:
                if not detail["synthesis"]:
                    detail["synthesis"] = {
                        "verdict": "Confirmed Incident" if (rca.confidence or 0.8) > 0.7 else "Suspicious Activity",
                        "executive_summary": rca.root_cause,
                        "confidence_score": rca.confidence,
                        "severity_score": rec.risk_score if rec else 0.8,
                    }
                if rca.attack_chain:
                    detail["attack_phases"] = rca.attack_chain if isinstance(rca.attack_chain, list) else [str(rca.attack_chain)]

            audits = db.query(AuditRecord).filter(AuditRecord.investigation_id == investigation_id).all()
            if audits:
                detail["audit_trail"] = [
                    {
                        "action": a.action,
                        "actor": a.actor or "System Admin",
                        "details": a.details,
                        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                    }
                    for a in audits
                ]
    except Exception as db_err:
        logger.debug(f"Postgres detail error: {db_err}")

    # 3. Check In-Memory Store if not found
    for inv in IN_MEMORY_INVESTIGATIONS:
        if inv.get("workflow_id") == investigation_id:
            detail["status"] = inv.get("status", detail["status"])
            if inv.get("started_at") and not detail["started_at"]:
                detail["started_at"] = inv.get("started_at")
            if inv.get("completed_at") and not detail["completed_at"]:
                detail["completed_at"] = inv.get("completed_at")
            if inv.get("total_duration_ms") and not detail["duration_ms"]:
                detail["duration_ms"] = inv.get("total_duration_ms")
            if not detail["synthesis"] and inv.get("synthesis"):
                detail["synthesis"] = inv["synthesis"]
            if not detail["reports"] and inv.get("reports"):
                detail["reports"] = inv["reports"]
            break

    # 4. Extract & Synthesize Attack Graph, CoT, and Recommended Actions from Reports
    reports = detail.get("reports", {})
    
    # Check Triage
    triage = next((r for r in reports.values() if r.get("agent_name") == "triage_agent"), {})
    triage_findings = triage.get("findings", {})
    entities = triage_findings.get("entities_identified", [])
    if triage_findings.get("severity"):
        detail["severity"] = triage_findings["severity"]

    # Check Evidence & Discovery
    evidence = next((r for r in reports.values() if r.get("agent_name") == "evidence_agent"), {})
    evidence_findings = evidence.get("findings", {})
    entity_graph_raw = evidence_findings.get("entity_graph", {})
    relationships_raw = evidence_findings.get("relationships", [])

    # Check RCA
    rca = next((r for r in reports.values() if r.get("agent_name") == "rca_agent"), {})
    rca_findings = rca.get("findings", {})
    if rca_findings:
        if rca_findings.get("chain_of_thought_verification"):
            detail["chain_of_thought"] = rca_findings["chain_of_thought_verification"]
        if rca_findings.get("attack_phases"):
            detail["attack_phases"] = rca_findings["attack_phases"]
        if rca_findings.get("root_cause") and not detail["synthesis"].get("executive_summary"):
            detail["synthesis"]["executive_summary"] = rca_findings["root_cause"]

    # Check Response
    resp = next((r for r in reports.values() if r.get("agent_name") == "response_agent"), {})
    resp_findings = resp.get("findings", {})
    if resp_findings.get("actions_recommended"):
        detail["actions_recommended"] = resp_findings["actions_recommended"]

    # Build Graph Structure (Nodes & Edges) for Canvas Rendering
    nodes = []
    edges = []
    seen_nodes = set()

    # Add entities from triage or evidence
    all_raw_entities = entities
    if entity_graph_raw:
        for eid, edata in entity_graph_raw.items():
            etype = edata.get("type", "unknown") if isinstance(edata, dict) else "entity"
            ename = edata.get("id", eid) if isinstance(edata, dict) else eid
            risk = edata.get("risk_score", 0.5) if isinstance(edata, dict) else 0.5
            if ename not in seen_nodes:
                nodes.append({
                    "id": str(ename),
                    "type": etype,
                    "name": str(ename),
                    "risk_score": risk,
                    "compromised": risk >= 0.7,
                })
                seen_nodes.add(str(ename))

    for ent in all_raw_entities:
        ename = ent.get("id") or ent.get("name") or "unknown"
        etype = ent.get("type", "unknown")
        if str(ename) not in seen_nodes:
            risk = 0.8 if etype in ("file", "ip") else 0.5
            nodes.append({
                "id": str(ename),
                "type": etype,
                "name": str(ename),
                "risk_score": risk,
                "compromised": risk >= 0.7,
            })
            seen_nodes.add(str(ename))

    # Add edges
    for rel in relationships_raw:
        if isinstance(rel, dict) and "source" in rel and "target" in rel:
            src = rel["source"].split(":")[-1]
            tgt = rel["target"].split(":")[-1]
            edges.append({
                "source": src,
                "target": tgt,
                "label": rel.get("type", "relates_to")
            })

    # Default fallback edges between nodes if no explicit relationships
    if nodes and not edges:
        primary_host = next((n["id"] for n in nodes if n["type"] == "host"), None)
        if primary_host:
            for n in nodes:
                if n["id"] != primary_host:
                    lbl = "runs_on" if n["type"] in ("file", "process") else "connected_to" if n["type"] == "ip" else "logged_into"
                    edges.append({"source": n["id"], "target": primary_host, "label": lbl})

    detail["attack_graph"] = {"nodes": nodes, "edges": edges}

    return detail


@router.get("/investigations/{investigation_id}/ledger")
async def get_investigation_ledger(investigation_id: str):
    """
    Retrieve the full replayable Investigation Ledger for an investigation:
    every agentic LLM call (supervisor decisions, triage/RCA/response synthesis,
    compression semantic summarization) in order, including the exact prompt
    sent, the model's response, and the resulting structured decision.
    """
    from backend.services.investigation_ledger import investigation_ledger

    entries = investigation_ledger.replay(investigation_id)
    return {
        "investigation_id": investigation_id,
        "total_steps": len(entries),
        "entries": [e.to_dict() for e in entries],
    }


@router.get("/investigations/{investigation_id}/ledger/cost")
async def get_investigation_ledger_cost(investigation_id: str):
    """
    Retrieve an aggregated token/latency cost breakdown (overall and per-agent)
    for an investigation, derived from its Investigation Ledger entries.
    """
    from backend.services.investigation_ledger import investigation_ledger

    return investigation_ledger.get_cost_summary(investigation_id)


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
                response_report = next((r for r in reports.values() if r.get("agent_name") == "response_agent"), {})
                actions = response_report.get("findings", {}).get("actions_recommended", [])
                
                # Get entities from Triage agent
                triage_report = next((r for r in reports.values() if r.get("agent_name") == "triage_agent"), {})
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
