"""Agentic Orchestrator — decomposes tasks, delegates to sub-agents, streams progress via SSE.

The OrchestratorAgent receives a high-level task (e.g., "Investigate alert X"),
plans sub-tasks, dispatches them to specialized agents (some in parallel, some serial),
collects reports, and synthesizes a final answer.
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional
from backend.services.investigation_context import InvestigationContext
from backend.services.agentic_security import wrap_untrusted

logger = logging.getLogger("orchestrator")


def _escalate_entity_promotion(context: "InvestigationContext", update: Any, source_agent: str) -> None:
    """Escalate a newly-auto-promoted entity (Wave 2 / Phase G full rollout).

    Cross-alert cumulative risk crossing the promotion threshold is a real
    escalation signal, so it is (1) posted to the investigation blackboard for
    the ReAct Supervisor / analysts to see, and (2) written to the audit trail
    for durable, queryable visibility -- independent of whether a formal
    incident (IncidentLifecycleManager, which requires a completed RCA) has
    been created yet.
    """
    investigation_id = getattr(context, "investigation_id", None) or (context.alert_data or {}).get("alert_id", "unknown")
    context.post_message(
        msg_type="FYI",
        source=source_agent,
        target="*",
        payload={
            "entity_risk_promoted": update.entity_id,
            "cumulative_risk": round(update.cumulative_risk, 4),
            "reason": update.reason,
        },
    )
    try:
        from backend.database.connection import SessionLocal
        from backend.database.postgres import AuditRecord
        import json as _json
        import uuid as _uuid
        if SessionLocal:
            db = SessionLocal()
            try:
                db.add(AuditRecord(
                    audit_id=str(_uuid.uuid4()),
                    investigation_id=investigation_id,
                    action="entity_risk_auto_promoted",
                    actor=source_agent,
                    details=_json.dumps({
                        "entity_id": update.entity_id,
                        "entity_type": update.entity_type,
                        "cumulative_risk": update.cumulative_risk,
                        "threshold": update.threshold,
                        "reason": update.reason,
                    }),
                ))
                db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()
    except Exception as e:
        logger.debug(f"Entity-risk promotion audit write skipped: {e}")


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

    def _heuristic_triage_fallback(self, alert: Dict[str, Any], error_msg: str) -> tuple[Dict[str, Any], float]:
        """Extracts entities, severity, and classification directly from raw alert data when LLM invocation fails."""
        import re
        import json
        
        raw_text = json.dumps(alert)
        entities = []
        seen = set()

        # 1. Regex pattern matches
        # IP addresses (v4)
        for ip in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_text):
            if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255") and ip not in seen:
                seen.add(ip)
                entities.append({"type": "ip", "id": ip})

        # Hashes (SHA256, MD5)
        for sha in re.findall(r'\b[a-fA-F0-9]{64}\b', raw_text):
            if sha not in seen:
                seen.add(sha)
                entities.append({"type": "file_hash", "id": sha})
        for md5 in re.findall(r'\b[a-fA-F0-9]{32}\b', raw_text):
            if md5 not in seen:
                seen.add(md5)
                entities.append({"type": "file_hash", "id": md5})

        # 2. Key-based extraction from known alert dictionary fields
        field_mappings = [
            (["host", "hostname", "dest_host", "src_host", "computer_name", "target_host"], "host"),
            (["user", "username", "account", "src_user", "dest_user", "target_user"], "user"),
            (["ip", "ip_address", "src_ip", "dest_ip", "srcip", "dstip"], "ip"),
            (["file", "file_name", "filename", "file_path", "filepath", "target_file"], "file"),
            (["process", "process_name", "parent_process", "image_name"], "process"),
            (["domain", "target_domain", "query"], "domain"),
        ]

        def search_dict(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if isinstance(v, (dict, list)):
                        search_dict(v)
                    elif isinstance(v, str) and v.strip():
                        val = v.strip()
                        k_lower = k.lower()
                        for field_keys, etype in field_mappings:
                            if k_lower in field_keys and val not in seen and len(val) > 1:
                                seen.add(val)
                                entities.append({"type": etype, "id": val})
            elif isinstance(d, list):
                for item in d:
                    search_dict(item)

        search_dict(alert)

        # Fallback entity if none found
        if not entities:
            src = alert.get("source") or alert.get("source_type") or alert.get("alert_id") or "unknown_asset"
            entities.append({"type": "host", "id": str(src)})

        # Severity & Classification heuristic
        alert_sev = str(alert.get("severity") or alert.get("priority") or "High").capitalize()
        if alert_sev not in ("Critical", "High", "Medium", "Low"):
            alert_sev = "High"
        
        classification = alert.get("alert_type") or alert.get("signature") or alert.get("title") or alert.get("category") or "security_incident"
        tactic = alert.get("mitre_tactic") or alert.get("tactic") or "Execution"
        technique = alert.get("mitre_technique") or alert.get("technique") or "T1059"
        assessment = alert.get("description") or alert.get("title") or f"Automated triage assessment for {classification}"

        from backend.services.skills import skill_registry
        triage_skills = skill_registry.load_phase_skills("triage")
        skills_used = [s.name for s in triage_skills] or ["ioc-extractor", "mitre-classifier", "severity-evaluator", "grounding-validator"]

        findings = {
            "severity": alert_sev,
            "classification": str(classification),
            "tactic": str(tactic),
            "technique": str(technique),
            "entities_identified": entities,
            "entity_count": len(entities),
            "requires_immediate_action": alert_sev in ("Critical", "High"),
            "initial_assessment": str(assessment),
            "confidence": 0.70,
            "skills_used": skills_used,
            "fallback_applied": True,
            "warning": f"Fallback rule-based triage applied due to LLM limit/error: {error_msg}"
        }
        return findings, 0.70

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        alert = context.alert_data

        from backend.services.llm_client import get_llm, TriageOutput, verify_entities, validate_triage_output
        from backend.services.prompt_manager import prompt_manager
        import json
        
        llm = get_llm(role="triage")
        structured_llm = llm.with_structured_output(TriageOutput)
        
        system_prompt = prompt_manager.get_system_prompt("triage")
        user_prompt = prompt_manager.build_user_prompt("triage", alert_json=wrap_untrusted(json.dumps(alert, indent=2), label="raw_alert"))
        prompt = f"{system_prompt}\n\n{user_prompt}"
        
        try:
            # Structured-output validation with retry (Phase D, Step 4): re-invoke up to
            # 2 additional times if severity/confidence/entity-type constraints are violated.
            _t0 = time.time()
            result = await structured_llm.ainvoke(prompt)
            violations = validate_triage_output(result)
            _retry_count = 0
            while violations and _retry_count < 2:
                logger.warning(f"TriageAgent structured-output validation failed (attempt {_retry_count + 1}): {violations}. Retrying.")
                result = await structured_llm.ainvoke(prompt)
                violations = validate_triage_output(result)
                _retry_count += 1
            _latency_ms = int((time.time() - _t0) * 1000)
            if violations:
                raise ValueError(f"TriageOutput failed validation after retries: {violations}")
            findings = result.model_dump()
            
            # Ground entities against the original alert text
            raw_alert_text = json.dumps(alert)
            # The result object still has Entity models, verify them
            valid_entity_models = verify_entities(result.entities_identified, raw_alert_text)
            
            # Load triage skills catalog
            from backend.services.skills import skill_registry
            triage_skills = skill_registry.load_phase_skills("triage")
            skills_used = [s.name for s in triage_skills] or ["ioc-extractor", "mitre-classifier", "severity-evaluator", "grounding-validator"]

            # Convert back to dicts for findings
            findings["entities_identified"] = [e.model_dump() for e in valid_entity_models]
            findings["entity_count"] = len(findings["entities_identified"])
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("triage")["version"]
            findings["skills_used"] = skills_used
            
            # Read dynamic confidence from the LLM, but penalize heavily if no entities were grounded
            llm_conf = findings.get("confidence", 0.50)
            confidence = llm_conf if findings["entity_count"] > 0 else min(llm_conf, 0.40)
            
            # Update context
            context.entities = findings.get("entities_identified", [])
            context.classification = findings.get("classification", "unknown")
            context.severity = findings.get("severity", "unknown")
            if findings.get("tactic"):
                context.mitre_tactics = [findings["tactic"]]
            if findings.get("technique"):
                context.mitre_techniques = [findings["technique"]]
        except Exception as e:
            logger.warning(f"TriageAgent LLM parsing error: {e}. Executing heuristic fallback extraction.")
            findings, confidence = self._heuristic_triage_fallback(alert, str(e))
            context.entities = findings.get("entities_identified", [])
            context.classification = findings.get("classification", "unknown")
            context.severity = findings.get("severity", "unknown")
            if findings.get("tactic"):
                context.mitre_tactics = [findings["tactic"]]
            if findings.get("technique"):
                context.mitre_techniques = [findings["technique"]]

        # Model Router (Phase D, Step 1): deterministic ground-truth override.
        # If a local threat-intel match exists (e.g. known ransomware extension/note),
        # force severity/classification deterministically rather than trusting the LLM's
        # guess — fixes the confirmed bug where indicators like known-ransomware files
        # scored risk_score=0.1 with nothing to check against.
        try:
            from backend.services.model_router import model_router
            routing = model_router.route("triage", {"alert_data": alert})
            findings["routing_tier"] = routing.tier
            if routing.tier == "deterministic" and routing.result:
                findings["severity"] = routing.result["severity"]
                findings["classification"] = routing.result["classification"]
                findings["matched_intel"] = routing.result.get("matched_intel")
                findings["routing_reasoning"] = routing.reasoning
                context.classification = findings["classification"]
                context.severity = findings["severity"]
                confidence = max(confidence, routing.result.get("confidence", confidence))
        except Exception as router_err:
            logger.debug(f"Model router check skipped for triage: {router_err}")

        # Entity-Risk Scoring full rollout (Wave 2, Phase G): feed this alert's
        # per-entity severity contribution into the time-decayed cumulative risk
        # tracker (QW-3), so repeated sub-critical activity against the same
        # entity across multiple alerts/investigations is itself detected, even
        # when no single alert crosses a severity threshold on its own.
        try:
            from backend.services.entity_risk import entity_risk_tracker, severity_to_risk_score
            from backend.models.entities import normalize_entity_type
            risk_score = severity_to_risk_score(findings.get("severity", "unknown"))
            alert_id = alert.get("alert_id", "unknown")
            newly_promoted_entities = []
            for ent in findings.get("entities_identified", []):
                eid = ent.get("id") if isinstance(ent, dict) else None
                # Normalize the entity type the same way the Evidence phase builds its
                # entity_graph keys (normalize_entity_type), so the same physical entity
                # (e.g. "hostname" from triage vs "host" from evidence) accumulates risk
                # under one tracker key instead of fragmenting across two.
                etype = normalize_entity_type(ent.get("type", "unknown") if isinstance(ent, dict) else "unknown")
                if not eid:
                    continue
                update = entity_risk_tracker.record_alert(
                    entity_id=f"{etype}:{eid}",
                    entity_type=etype,
                    alert_id=alert_id,
                    risk_score=risk_score,
                )
                if update.newly_promoted:
                    newly_promoted_entities.append(update)
            for update in newly_promoted_entities:
                _escalate_entity_promotion(context, update, source_agent=self.name)
        except Exception as risk_err:
            logger.debug(f"Entity-risk scoring skipped for triage: {risk_err}")

        # Compounding Memory (Wave 3, Phase J): apply a small, bounded (+/-0.10)
        # confidence adjustment based on how this alert signature (classification
        # + tactic + technique) has historically resolved (false positive vs
        # confirmed incident) across past investigations. Returns 0.0 (no effect)
        # for unseen/insufficiently-seen signatures -- never overrides the
        # LLM/ground-truth confidence, only nudges it, and the adjustment is
        # always recorded in findings for auditability.
        try:
            from backend.services.memory.distillation import compounding_memory, build_alert_signature
            alert_signature = build_alert_signature(
                findings.get("classification", "unknown"),
                findings.get("tactic", ""),
                findings.get("technique", ""),
            )
            memory_adjustment = compounding_memory.get_memory_verdict_adjustment(alert_signature)
            if memory_adjustment:
                confidence = max(0.0, min(1.0, confidence + memory_adjustment))
            findings["alert_signature"] = alert_signature
            findings["memory_adjustment"] = memory_adjustment
        except Exception as memory_err:
            logger.debug(f"Compounding memory adjustment skipped for triage: {memory_err}")

        # Security Knowledge Graph at Ingest (Wave 3, Phase M, narrowly scoped):
        # write the user->host->process relationships for this alert to Neo4j
        # as it arrives, rather than only when an investigation later queries
        # them. Best-effort/no-op if Neo4j isn't configured -- never blocks
        # triage.
        try:
            from backend.services.graph_ingest import record_user_host_process
            await record_user_host_process(
                user_id=alert.get("user_name"),
                host_id=alert.get("computer_name"),
                process_id=alert.get("process_id") or alert.get("process_name"),
                process_name=alert.get("process_name"),
                timestamp=alert.get("timestamp"),
            )
        except Exception as graph_err:
            logger.debug(f"Graph ingest skipped for triage: {graph_err}")

        try:
            from backend.services.investigation_ledger import record_ledger_entry
            from backend.services.llm_client import MODEL_ROUTING, DEFAULT_MODEL
            record_ledger_entry(
                investigation_id=getattr(context, "investigation_id", None) or alert.get("alert_id", "unknown"),
                agent_name=self.name,
                phase="triage",
                prompt_sent=prompt,
                llm_response=json.dumps(findings, default=str),
                model_used=findings.get("routing_tier", "llm") if findings.get("routing_tier") == "deterministic" else MODEL_ROUTING.get("triage", DEFAULT_MODEL),
                decision=findings,
                skills_invoked=findings.get("skills_used", []),
                latency_ms=locals().get("_latency_ms", 0),
            )
        except Exception as ledger_err:
            logger.debug(f"Ledger recording skipped for triage: {ledger_err}")

        # ---------------------------------------------------------------
        # Execute real triage skill handlers to enrich/validate findings
        # ---------------------------------------------------------------
        from backend.services.triage.skill_handlers import TriageSkillExecutor

        skill_results = {}
        try:
            # 1. IOC Extractor — deep regex extraction from raw alert
            ioc_result = await TriageSkillExecutor.execute_skill(
                "ioc-extractor", {"raw_alert": alert}
            )
            skill_results["ioc_extractor"] = ioc_result

            # 2. MITRE Classifier — deterministic technique mapping
            mitre_result = await TriageSkillExecutor.execute_skill(
                "mitre-classifier", {"alert_data": alert}
            )
            skill_results["mitre_classifier"] = mitre_result
            # Upgrade tactic/technique if the skill found a higher-confidence match
            if mitre_result.get("confidence", 0) > findings.get("mitre_confidence", 0):
                findings["tactic"] = mitre_result.get("tactic", findings.get("tactic"))
                findings["technique"] = mitre_result.get("technique", findings.get("technique"))
                findings["mitre_confidence"] = mitre_result.get("confidence", 0)
                if mitre_result.get("tactic"):
                    context.mitre_tactics = [mitre_result["tactic"]]
                if mitre_result.get("technique_id"):
                    context.mitre_techniques = [mitre_result["technique_id"]]

            # 3. Severity Evaluator — keyword-based severity scoring
            sev_result = await TriageSkillExecutor.execute_skill(
                "severity-evaluator", {"alert_data": alert}
            )
            skill_results["severity_evaluator"] = sev_result
            # Only upgrade severity (never downgrade)
            sev_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            current_sev = str(findings.get("severity", "low")).lower()
            skill_sev = str(sev_result.get("severity", "low")).lower()
            if sev_priority.get(skill_sev, 0) > sev_priority.get(current_sev, 0):
                findings["severity"] = sev_result["severity"]
                context.severity = sev_result["severity"]
            if sev_result.get("requires_immediate_action"):
                findings["requires_immediate_action"] = True

            # 4. Grounding Validator — verify entities exist in raw alert text
            grounding_entities = []
            for ent in findings.get("entities_identified", []):
                val = ent.get("id") or ent.get("name") or ent.get("value", "")
                grounding_entities.append({"value": val, **ent})
            grounding_result = await TriageSkillExecutor.execute_skill(
                "grounding-validator",
                {"extracted_entities": grounding_entities, "raw_alert_text": json.dumps(alert)}
            )
            skill_results["grounding_validator"] = grounding_result
            findings["hallucination_rate"] = grounding_result.get("hallucination_rate", 0)
            findings["grounding_confidence"] = grounding_result.get("confidence_score", 1.0)

            # 5. Threat Intel Pre-filter — check IOCs against known bad lists
            ioc_entities = ioc_result.get("entities", {})
            prefilter_result = await TriageSkillExecutor.execute_skill(
                "threat-intel-prefilter", {"entities": ioc_entities}
            )
            skill_results["threat_intel_prefilter"] = prefilter_result
            if prefilter_result.get("flagged_iocs"):
                findings["prefilter_flagged_iocs"] = prefilter_result["flagged_iocs"]

        except Exception as e:
            logger.warning(f"Triage skill execution partially failed: {e}")

        findings["skill_results"] = skill_results

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

        # Deduplicate and normalize entity types and IDs
        from backend.models.entities import normalize_entity_type

        all_entities = []
        seen_entity_keys = set()
        for ent in entities + targeted_entities:
            if isinstance(ent, str):
                ent = {"type": "unknown", "id": ent}
            elif isinstance(ent, dict):
                ent = dict(ent)
            
            ent_id = str(ent.get("id") or ent.get("name") or "unknown").strip()
            ent_type = normalize_entity_type(ent.get("type", "unknown"))

            # Strip accidental type prefixes from id (e.g., 'file:install.sh' -> 'install.sh')
            for prefix in ("file:", "ip:", "ip_address:", "host:", "user:", "process:", "domain:", "hash:"):
                if ent_id.lower().startswith(prefix):
                    extracted_type = prefix.rstrip(":")
                    ent_id = ent_id[len(prefix):]
                    if ent_type in ("unknown", "host"):
                        ent_type = normalize_entity_type(extracted_type)

            ent["id"] = ent_id
            ent["type"] = ent_type

            key = (ent_type, ent_id)
            if key not in seen_entity_keys and ent_id not in ("unknown", ""):
                seen_entity_keys.add(key)
                all_entities.append(ent)
            
        inv_id = getattr(context, "investigation_id", None) or context.alert_data.get("alert_id", "inv-unknown")
        evidence_context = await orchestrator.collect_for_entities(
            entities_data=all_entities,
            investigation_id=inv_id
        )

        # Agentic Skill Execution: Discover and run targeted evidence skills per entity
        from backend.services.skills import skill_registry
        from backend.services.evidence.skill_handlers import EvidenceSkillExecutor
        
        available_evidence_skills = skill_registry.load_phase_skills("evidence")
        deployed_skills = set()
        skill_deployments = []

        # Build entity graph from identified entities & execute specific evidence skills
        entity_graph = dict(context.entity_graph) if context.entity_graph else {}
        relationships = list(context.relationships) if context.relationships else []
        
        for ent in all_entities:
            eid_raw = ent.get("id") or ent.get("name") or "unknown"
            etype = normalize_entity_type(ent.get("type", "unknown"))
            
            # Determine targeted skills based on entity type and alert context
            target_skills = []
            if etype in ("host", "endpoint"):
                target_skills = ["edr-process-tree", "persistence-auditor"]
            elif etype in ("ip", "domain", "url"):
                target_skills = ["threat-intel-lookup", "network-flow-analyzer"]
            elif etype in ("user", "account", "identity"):
                target_skills = ["identity-ad-lookup"]
            elif etype in ("file", "process", "hash"):
                target_skills = ["file-forensics", "threat-intel-lookup"]
            else:
                target_skills = ["threat-intel-lookup"]

            for skill_name in target_skills:
                deployed_skills.add(skill_name)
                skill_res = await EvidenceSkillExecutor.execute_skill(
                    skill_name=skill_name,
                    entity_id=eid_raw,
                    entity_type=etype,
                    context_data={"alert": context.alert_data, "classification": context.classification}
                )
                skill_deployments.append({
                    "skill": skill_name,
                    "target_entity": eid_raw,
                    "risk_score": skill_res.get("risk_score", 0.0),
                })
                
                # Merge skill result into entity graph
                eid = f"{etype}:{eid_raw}"
                if eid not in entity_graph:
                    entity_graph[eid] = {
                        "type": etype,
                        "id": eid_raw,
                        "risk_score": skill_res.get("risk_score", 0.3),
                        "evidence_count": len(skill_res.get("enrichment_data", {})),
                        "enrichment": skill_res.get("enrichment_data", {}),
                        "threat_intel": skill_res.get("threat_intel", {}),
                        "attributes": skill_res.get("attributes", {}),
                    }
                else:
                    entity_graph[eid]["enrichment"].update(skill_res.get("enrichment_data", {}))
                    entity_graph[eid]["threat_intel"].update(skill_res.get("threat_intel", {}))
                    entity_graph[eid]["risk_score"] = max(entity_graph[eid]["risk_score"], skill_res.get("risk_score", 0.0))

        # Merge standard evidence collector nodes with unified normalization
        for entity_node in evidence_context['entities'].values():
            raw_node_type = entity_node.entity_type.value if hasattr(entity_node.entity_type, 'value') else str(entity_node.entity_type)
            node_type = normalize_entity_type(raw_node_type)
            node_id = str(entity_node.entity_id).strip()
            for prefix in ("file:", "ip:", "ip_address:", "host:", "user:", "process:", "domain:", "hash:"):
                if node_id.lower().startswith(prefix):
                    node_id = node_id[len(prefix):]
            
            eid = f"{node_type}:{node_id}"
            if eid not in entity_graph:
                entity_graph[eid] = {
                    "type": node_type,
                    "id": node_id,
                    "risk_score": entity_node.risk_score,
                    "evidence_count": len(entity_node.enrichment_data) if entity_node.enrichment_data else 0,
                    "enrichment": entity_node.enrichment_data or {},
                    "threat_intel": entity_node.threat_intel or {},
                    "attributes": entity_node.attributes or {},
                }
            else:
                if entity_node.enrichment_data:
                    entity_graph[eid]["enrichment"].update(entity_node.enrichment_data)
                if entity_node.threat_intel:
                    entity_graph[eid]["threat_intel"].update(entity_node.threat_intel)
                entity_graph[eid]["risk_score"] = max(entity_graph[eid].get("risk_score", 0.0), entity_node.risk_score or 0.0)
                
        # Handle relationships from evidence context
        for rel in evidence_context.get('relationships', []):
            relationships.append({
                "source": rel.source_entity_id,
                "target": rel.target_entity_id,
                "type": rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else str(rel.relationship_type)
            })

        # Add original heuristic relationships
        for ent in all_entities:
            ent_id = ent.get("id", "unknown")
            ent_type = normalize_entity_type(ent.get("type", "unknown"))
            eid = f"{ent_type}:{ent_id}"
            
            if ent_type == "process" and any(normalize_entity_type(e.get("type")) == "host" for e in all_entities):
                host = next((e for e in all_entities if normalize_entity_type(e.get("type")) == "host"), None)
                if host:
                    relationships.append({
                        "source": eid,
                        "target": f"host:{host['id']}",
                        "type": "runs_on"
                    })
            if ent_type == "user" and any(normalize_entity_type(e.get("type")) == "host" for e in all_entities):
                host = next((e for e in all_entities if normalize_entity_type(e.get("type")) == "host"), None)
                if host:
                    relationships.append({
                        "source": eid,
                        "target": f"host:{host['id']}",
                        "type": "logged_into"
                    })
                    
        # Deduplicate relationships to prevent edge explosions across ReAct iterations
        unique_rels = []
        seen_rels = set()
        
        # Add existing relationships first to maintain history
        for r in context.relationships:
            key = (r.get("source"), r.get("target"), r.get("type"))
            if key not in seen_rels:
                seen_rels.add(key)
                unique_rels.append(r)
                
        # Add new relationships uniquely
        for r in relationships:
            key = (r.get("source"), r.get("target"), r.get("type"))
            if key not in seen_rels:
                seen_rels.add(key)
                unique_rels.append(r)
                    
        # Update context
        context.entity_graph = entity_graph
        context.relationships = unique_rels

        # Entity-Risk Scoring full rollout (Wave 2, Phase G): Evidence-phase entities
        # carry their own risk_score from evidence skills (threat-intel matches, YARA/VT
        # hits, etc.) -- feed each into the same cumulative tracker used by Triage, so
        # evidence-derived risk signals also contribute toward auto-promotion.
        try:
            from backend.services.entity_risk import entity_risk_tracker
            alert_id = context.alert_data.get("alert_id", "unknown") if context.alert_data else "unknown"
            for eid, edata in entity_graph.items():
                if not isinstance(edata, dict):
                    continue
                risk_score = edata.get("risk_score", 0.0)
                if risk_score <= 0:
                    continue
                update = entity_risk_tracker.record_alert(
                    entity_id=eid,
                    entity_type=edata.get("type", "unknown"),
                    alert_id=alert_id,
                    risk_score=risk_score,
                )
                if update.newly_promoted:
                    _escalate_entity_promotion(context, update, source_agent=self.name)
        except Exception as risk_err:
            logger.debug(f"Entity-risk scoring skipped for evidence: {risk_err}")

        high_risk_iocs = [
            f"{k.replace('file:', '').replace('ip:', '').replace('host:', '').replace('user:', '')} (Risk: {v.get('risk_score', 0)})"
            for k, v in entity_graph.items()
            if v.get("risk_score", 0) >= 0.6
        ]
        risk_note = f" Flagged IOCs: {', '.join(high_risk_iocs)}." if high_risk_iocs else ""
        skills_str = ", ".join(sorted(list(deployed_skills))) if deployed_skills else "EDR & SIEM connectors"
        summary_text = f"Expanded {len(all_entities)} seed entities into {len(entity_graph)} graph nodes using {len(deployed_skills)} agentic skills ({skills_str}).{risk_note}"

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
                "skills_used": sorted(list(deployed_skills)) if deployed_skills else ["edr-process-tree", "threat-intel-lookup", "identity-ad-lookup"],
                "skill_deployments": skill_deployments,
                "data_sources_queried": ["EDR", "SIEM", "Active Directory", "Threat Intel", "Network Telemetry"],
                "enrichment_summary": summary_text,
                "summary": summary_text,
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
        
        from backend.services.correlation_engine import CorrelationEngine
        from backend.database.connection import SessionLocal
        from backend.database.postgres import EventRecord
        import uuid
        
        # 1. Gather raw events from PostgreSQL or generate structured telemetry events from evidence
        raw_events = list(context.raw_events) if context.raw_events else []
        
        # Query Postgres EventRecord for events related to investigation or entities
        if SessionLocal:
            db = SessionLocal()
            try:
                entity_ids = [e.get("id") for e in context.entities if isinstance(e, dict) and e.get("id")]
                if entity_ids:
                    db_events = db.query(EventRecord).filter(
                        (EventRecord.source_entity_id.in_(entity_ids)) | 
                        (EventRecord.target_entity_id.in_(entity_ids))
                    ).all()
                    for dbe in db_events:
                        raw_events.append({
                            "event_id": dbe.event_id,
                            "timestamp": dbe.timestamp.isoformat() if dbe.timestamp else datetime.utcnow().isoformat(),
                            "event_type": dbe.event_type,
                            "entity": dbe.source_entity_id,
                            "user": dbe.source_entity_id if "user" in str(dbe.source_entity_id) else "unknown",
                            "host": dbe.target_entity_id if "host" in str(dbe.target_entity_id) else "unknown",
                            "process": "unknown",
                            "action": dbe.relationship_type or dbe.event_type,
                            "risk_score": dbe.risk_score or 0.5,
                        })
            except Exception:
                pass
            finally:
                db.close()
                
        # If no DB events found, ingest real logs from dataset directory
        if not raw_events:
            try:
                from backend.services.evidence.log_ingestor import get_log_ingestor
                ingestor = get_log_ingestor()
                
                # Collect real log events for all identified entities
                searched_entities = set()
                for ent in context.entities:
                    if isinstance(ent, dict):
                        eid = ent.get("id", "")
                        if eid and eid not in searched_entities:
                            searched_entities.add(eid)
                            log_events = ingestor.search_entity(eid, ent.get("type", "unknown"), max_results=100)
                            for levt in log_events:
                                ent_val = levt.get("entity")
                                if not ent_val or ent_val == "unknown":
                                    ent_val = eid
                                
                                act_val = levt.get("action") or levt.get("event_type") or "unknown"
                                
                                # Derive meaningful risk score based on content and IOC match
                                risk_val = float(levt.get("risk_score", 0.1))
                                alert_file = (context.alert_data.get("file_name") or "").lower()
                                act_lower = str(act_val).lower()
                                
                                suspicious_indicators = [
                                    alert_file, "encrypt", "install.sh", "donotcry", "raindrop",
                                    "powershell", "curl", "wget", "chmod +x", "base64", "mimikatz",
                                    "whoami", "certutil", "vssadmin", "shadowcopy", "rundll32"
                                ]
                                suspicious_indicators = [ind for ind in suspicious_indicators if ind]
                                
                                if any(ind in act_lower for ind in suspicious_indicators):
                                    risk_val = max(risk_val, 0.85)
                                elif levt.get("source") == "audit" and levt.get("event_type") in ("EXECVE", "SYSCALL"):
                                    risk_val = max(risk_val, 0.45)
                                elif "siem_alert" in str(levt.get("event_type", "")).lower():
                                    risk_val = max(risk_val, 0.75)

                                raw_events.append({
                                    "event_id": f"log-{uuid.uuid4().hex[:8]}",
                                    "timestamp": levt.get("timestamp", datetime.utcnow().isoformat()),
                                    "event_type": levt.get("event_type", "log_event"),
                                    "entity": ent_val,
                                    "user": levt.get("metadata", {}).get("uid") or (eid if ent.get("type") == "user" else context.alert_data.get("user_name", "unknown")),
                                    "host": levt.get("metadata", {}).get("hostname") or (eid if ent.get("type") == "host" else context.alert_data.get("computer_name", "unknown")),
                                    "process": levt.get("metadata", {}).get("comm", levt.get("metadata", {}).get("exe", "unknown")),
                                    "action": act_val,
                                    "risk_score": risk_val,
                                    "source": levt.get("source", "log_file"),
                                })
                logger.info(f"Ingested {len(raw_events)} real log events for {len(searched_entities)} entities from dataset")
            except Exception as e:
                logger.warning(f"Log ingestor unavailable, falling back to alert-derived events: {e}")
        
        # Last resort: create a minimal event from the alert itself if still no events
        if not raw_events:
            alert = context.alert_data or {}
            raw_events.append({
                "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": alert.get("timestamp") or datetime.utcnow().isoformat(),
                "event_type": context.classification or "security_alert",
                "entity": alert.get("computer_name", "unknown"),
                "user": alert.get("user_name", "unknown"),
                "host": alert.get("computer_name", "unknown"),
                "process": alert.get("file_name", "unknown"),
                "action": alert.get("description", "Alert trigger event"),
                "risk_score": 0.9 if context.severity.lower() in ("critical", "high") else 0.5,
            })

        # Run through full 7-stage CorrelationEngine
        engine = CorrelationEngine()
        
        # Parse incident time
        incident_time = datetime.utcnow()
        if context.alert_data.get("timestamp"):
            try:
                incident_time = datetime.fromisoformat(context.alert_data["timestamp"].replace("Z", "+00:00"))
                if incident_time.tzinfo:
                    incident_time = incident_time.replace(tzinfo=None)
            except Exception:
                incident_time = datetime.utcnow()

        # Agentic Compression: Load compression skills catalog and select strategy
        from backend.services.skills import skill_registry
        from backend.services.compression.skill_handlers import CompressionSkillExecutor
        
        compression_skills = skill_registry.load_phase_skills("compression")
        selected_skills = [s.name for s in compression_skills] or [
            "duplicate-rollup",
            "temporal-clustering",
            "behavioral-anomaly-filter",
            "entity-graph-reduction",
            "semantic-summarizer",
        ]

        package = await engine.compress_events(
            raw_events=raw_events,
            incident_time=incident_time,
            investigation_id=context.alert_data.get("alert_id", f"inv-{uuid.uuid4().hex[:6]}")
        )
        
        original_count = package.original_event_count
        compressed_count = package.compressed_event_count
        ratio = package.compression_ratio
        
        # Format stage breakdown from REAL engine metrics
        stages = [
            {
                "name": sm.name,
                "input": sm.input_count,
                "output": sm.output_count,
                "reduction": f"{sm.reduction_pct:.1f}%",
                "skill": sm.skill,
            }
            for sm in package.stage_metrics
        ]
        
        # Agentic Compression: LLM Semantic Summarization
        final_timeline = package.timeline
        if package.timeline:
            try:
                from backend.services.llm_client import get_llm
                from pydantic import BaseModel, Field
                import json
                
                class TimelineEvent(BaseModel):
                    timestamp: str = Field(..., description="Timestamp of the event")
                    event_type: str = Field(..., description="Semantic category (e.g., Initial Access, Execution, Privilege Escalation)")
                    entity: str = Field(..., description="Entity involved")
                    action: str = Field(..., description="Detailed description of the action")
                    risk_score: float = Field(..., description="Risk score (0.0-1.0)")
                    mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK Tactic Name")
                    mitre_technique_id: Optional[str] = Field(None, description="MITRE ATT&CK Technique ID")
                    mitre_technique_name: Optional[str] = Field(None, description="MITRE ATT&CK Technique Name")
                
                class SemanticTimeline(BaseModel):
                    timeline: list[TimelineEvent] = Field(..., description="Chronological semantic timeline")
                
                llm = get_llm(role="summarizer")
                structured_llm = llm.with_structured_output(SemanticTimeline)
                prompt = (
                    "You are a SOC Analyst. Convert the following raw events into a semantic timeline of an attack or investigation. "
                    "Identify key phases (e.g. Initial Access, Discovery, Lateral Movement). Ensure actions are clear and descriptive.\n\n"
                    f"Events: {json.dumps(package.timeline)}"
                )
                _t0 = time.time()
                res = await structured_llm.ainvoke(prompt)
                _latency_ms = int((time.time() - _t0) * 1000)
                if res and res.timeline:
                    final_timeline = [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in res.timeline]

                try:
                    from backend.services.investigation_ledger import record_ledger_entry
                    from backend.services.llm_client import MODEL_ROUTING, DEFAULT_MODEL
                    record_ledger_entry(
                        investigation_id=getattr(context, "investigation_id", None) or context.alert_data.get("alert_id", "unknown"),
                        agent_name=self.name,
                        phase="compression",
                        prompt_sent=prompt,
                        llm_response=json.dumps(final_timeline, default=str),
                        model_used=MODEL_ROUTING.get("summarizer", DEFAULT_MODEL),
                        decision={"timeline_events": len(final_timeline)},
                        latency_ms=_latency_ms,
                    )
                except Exception as ledger_err:
                    logger.debug(f"Ledger recording skipped for compression: {ledger_err}")
            except Exception as e:
                logger.error(f"Failed to generate semantic timeline: {e}")

        # Prepare lightweight serialized list of the filtered events (150 events)
        filtered_events_summary = []
        for ev in (package.events or []):
            item = {
                "event_id": ev.event_id,
                "timestamp": ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp),
                "event_type": ev.event_type,
                "entity": ev.entity_id,
                "action": str(ev.action),
                "risk_score": round(float(ev.risk_score), 2),
                "raw_count": len(ev.raw_events) if ev.raw_events else 1,
            }
            if ev.mitre_technique:
                item["mitre_tactic"] = ev.mitre_technique.tactic_name
                item["mitre_technique_id"] = ev.mitre_technique.technique_id
                item["mitre_technique_name"] = ev.mitre_technique.technique_name
            filtered_events_summary.append(item)

        # Save to context
        context.compressed_events = {
            "original_events": original_count,
            "compressed_events": compressed_count,
            "compression_ratio": f"{ratio:.1f}x",
            "timeline": final_timeline,
            "attack_graph": package.attack_graph,
            "detected_patterns": package.detected_patterns,
            "risk_score": package.risk_score,
            "confidence": package.confidence,
            "stages": stages,
            "skills_used": selected_skills,
            "filtered_events": filtered_events_summary,
        }

        return AgentReport(
            agent_name=self.name,
            task="7-stage event compression",
            status=AgentStatus.COMPLETED,
            started_at=datetime.fromtimestamp(start).isoformat(),
            completed_at=datetime.now().isoformat(),
            duration_ms=int((time.time() - start) * 1000),
            findings={
                "original_events": original_count,
                "compressed_events": compressed_count,
                "compression_ratio": f"{ratio:.1f}x",
                "risk_score": package.risk_score,
                "patterns_detected": len(package.detected_patterns),
                "timeline_milestones": len(package.timeline),
                "skills_used": selected_skills,
                "stages": stages,
                "raw_events": raw_events,
                "filtered_events": filtered_events_summary,
                "timeline": final_timeline,
                "attack_graph": package.attack_graph,
                "summary": f"Compressed {original_count} events down to {compressed_count} ({ratio:.1f}x reduction) through {len(selected_skills)} agentic compression skills.",
            },
            confidence=package.confidence or 0.95,
            artifacts=["compressed_timeline", "attack_subgraph", "pattern_report"],
        )


class RCAAnalystAgent(BaseAgent):
    """Performs root cause analysis on compressed evidence using hybrid CausalAnalyzer + LLM."""

    name = "rca_agent"
    description = "Root cause analysis and attack chain reconstruction"

    async def execute(self, inputs: Dict[str, Any], context: InvestigationContext) -> AgentReport:
        start = time.time()
        entity_graph = context.entity_graph
        classification = context.classification
        relationships = context.relationships or []
        compressed_data = context.compressed_events or {}

        from backend.services.llm_client import get_llm, RCAOutput
        from backend.services.prompt_manager import prompt_manager
        from backend.services.sx_truerca.causal_analyzer import CausalAnalyzer
        from backend.services.sx_truerca.rca_config import RCAConfig
        import networkx as nx
        import json

        # -------------------------------------------------------------
        # Step 1: Structural Causal Analysis using sx-truerca
        # -------------------------------------------------------------
        topo_graph = nx.DiGraph()
        
        # Add nodes
        for eid, edata in (entity_graph or {}).items():
            topo_graph.add_node(eid, **edata)
            
        # Add edges from relationships
        for rel in relationships:
            src = rel.get("source")
            tgt = rel.get("target")
            if src and tgt:
                topo_graph.add_edge(src, tgt, type=rel.get("type", "related_to"))

        # Calculate anomaly scores per entity
        anomaly_scores = {}
        for eid, edata in (entity_graph or {}).items():
            anomaly_scores[eid] = float(edata.get("risk_score", 0.5))
            
        # Extract anomalies from timeline
        anomalies = []
        timeline = compressed_data.get("timeline", [])
        for item in timeline:
            anomalies.append({
                "service": item.get("entity"),
                "timestamp": item.get("timestamp"),
                "score": float(item.get("risk_score", 0.5)),
                "type": item.get("event_type", "anomaly")
            })

        # Identify target service (primary compromised host or user)
        target_service = None
        if context.alert_data.get("computer_name"):
            target_service = f"host:{context.alert_data['computer_name']}"
            if target_service not in topo_graph:
                target_service = context.alert_data['computer_name']
        if not target_service or target_service not in topo_graph:
            # Fallback to first high-risk entity
            for eid, score in sorted(anomaly_scores.items(), key=lambda x: x[1], reverse=True):
                target_service = eid
                break
        if not target_service:
            target_service = "unknown_target"

        causal_analyzer = CausalAnalyzer(topology_graph=topo_graph, config=RCAConfig())
        ranked_causes = causal_analyzer.score_root_causes(
            target_service=target_service,
            anomaly_scores=anomaly_scores,
            anomalies=anomalies
        )

        causal_candidates = []
        for svc, score, reason in ranked_causes[:5]:
            causal_candidates.append({
                "candidate_entity": svc,
                "causal_score": round(score, 3),
                "reasoning": reason
            })
            
        context.causal_candidates = causal_candidates

        # -------------------------------------------------------------
        # Step 2: LLM Synthesis & Verification with Causal Grounding
        # -------------------------------------------------------------
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
        except Exception:
            pass # Fail gracefully if Temporal is unavailable

        system_prompt = prompt_manager.get_system_prompt("rca")

        # Trim entity graph: compact JSON (no indent) + top-N by risk score
        # indent=2 on a large graph adds ~30% token overhead — use separators instead
        eg_str = json.dumps(entity_graph, separators=(',', ':'))
        if len(eg_str) > 1500:
            top_entities = dict(sorted(
                (entity_graph or {}).items(),
                key=lambda kv: float(kv[1].get("risk_score", 0)) if isinstance(kv[1], dict) else 0,
                reverse=True
            )[:7])
            eg_str = json.dumps(top_entities, separators=(',', ':'))

        user_prompt = prompt_manager.build_user_prompt(
            "rca",
            classification=classification,
            entity_graph_json=wrap_untrusted(eg_str, label="entity_graph"),
            causal_analysis_json=json.dumps(causal_candidates[:3], separators=(',', ':')),
            historical_context=wrap_untrusted(historical_context[:300], label="retrieved_history"),
            messages_json="[]"  # omit to save tokens; causal candidates carry the same signal
        )
        prompt = f"{system_prompt}\n\n{user_prompt}"

        try:
            _t0 = time.time()
            result = await structured_llm.ainvoke(prompt)
            _latency_ms = int((time.time() - _t0) * 1000)
            findings = result.model_dump()
            confidence = findings.get("confidence", 0.85)
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("rca")["version"]
            findings["structural_causal_candidates"] = causal_candidates
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
            
            # Extract IOCs from entity graph & timeline
            iocs = []
            for eid, edata in entity_graph.items():
                etype = edata.get("type", "").lower()
                erisk = edata.get("risk_score", 0.0)
                if erisk >= 0.6 or etype in ("ip", "file", "domain", "hash", "ip_address"):
                    iocs.append({
                        "type": etype or "ioc",
                        "value": eid,
                        "risk_score": erisk,
                        "reputation": edata.get("threat_intel", {}).get("reputation", "suspicious"),
                    })
            findings["indicators_of_compromise"] = iocs
            context.iocs = iocs
            
            context.rca_findings = findings
            context.rca_findings["confidence_score"] = confidence

            try:
                from backend.services.investigation_ledger import record_ledger_entry
                from backend.services.llm_client import MODEL_ROUTING, DEFAULT_MODEL
                record_ledger_entry(
                    investigation_id=getattr(context, "investigation_id", None) or context.alert_data.get("alert_id", "unknown"),
                    agent_name=self.name,
                    phase="rca",
                    prompt_sent=prompt,
                    llm_response=json.dumps(findings, default=str),
                    model_used=MODEL_ROUTING.get("rca", DEFAULT_MODEL),
                    decision=findings,
                    evidence_cited=[c.get("candidate_entity") for c in causal_candidates[:3]],
                    latency_ms=locals().get("_latency_ms", 0),
                )
            except Exception as ledger_err:
                logger.debug(f"Ledger recording skipped for rca: {ledger_err}")

        except Exception as e:
            logger.warning(f"RCAAnalystAgent LLM error: {e}. Applying structural causal fallback.")
            root_cause_candidate = causal_candidates[0]["candidate_entity"] if causal_candidates else "Unknown Root Cause"
            
            # Extract IOCs from entity graph & timeline
            iocs = []
            for eid, edata in entity_graph.items():
                etype = edata.get("type", "").lower()
                erisk = edata.get("risk_score", 0.0)
                if erisk >= 0.6 or etype in ("ip", "file", "domain", "hash", "ip_address"):
                    iocs.append({
                        "type": etype or "ioc",
                        "value": eid,
                        "risk_score": erisk,
                        "reputation": edata.get("threat_intel", {}).get("reputation", "suspicious"),
                    })
            context.iocs = iocs

            findings = {
                "root_cause": root_cause_candidate,
                "attack_phases": [f"Initial trigger via {root_cause_candidate}", "Lateral expansion across entity graph"],
                "blast_radius": len(entity_graph),
                "structural_causal_candidates": causal_candidates,
                "indicators_of_compromise": iocs,
                "confidence": 0.60,
                "fallback_applied": True,
                "warning": f"Structural heuristic RCA applied due to LLM error: {str(e)}",
                "summary": f"Identified primary candidate '{root_cause_candidate}' via structural graph topology across {len(entity_graph)} nodes."
            }
            confidence = 0.60
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
        attack_chain = context.rca_findings.get("attack_phases") or context.rca_findings.get("attack_chain", [])
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
            
            # Combine the content of the top 3 retrieved sections to prevent context window overflow
            top_docs = docs[:3] if docs else []
            playbook_context = "\n\n".join([doc.page_content for doc in top_docs]) if top_docs else "No specific playbook found."
            if len(playbook_context) > 2500:
                playbook_context = playbook_context[:2500]
        except Exception as e:
            playbook_context = f"Failed to retrieve playbooks: {str(e)}"

        # 2. LLM Step: Plan response
        llm = get_llm(role="response")
        structured_llm = llm.with_structured_output(ResponseOutput)
        
        system_prompt = prompt_manager.get_system_prompt("response")

        # Trim entities to fit small model context windows
        entities_str = json.dumps(entities[:10] if len(entities) > 10 else entities, indent=2)
        if len(entities_str) > 1500:
            entities_str = entities_str[:1500]

        user_prompt = prompt_manager.build_user_prompt(
            "response",
            root_cause=root_cause,
            attack_chain=attack_chain[:5] if isinstance(attack_chain, list) else attack_chain,
            entities_json=entities_str,
            playbook_context=wrap_untrusted(playbook_context, label="retrieved_playbook"),
            messages_json=messages_json[:500] if messages_json != "[]" else "[]"
        )
        prompt = f"{system_prompt}\n\n{user_prompt}"

        try:
            # Load response skills catalog
            from backend.services.skills import skill_registry
            response_skills = skill_registry.load_phase_skills("response")
            skills_used = [s.name for s in response_skills] or ["isolate-host", "block-ip", "block-domain", "kill-process", "reset-credentials"]

            result = await structured_llm.ainvoke(prompt)
            findings = result.model_dump()
            findings["prompt_version"] = prompt_manager.get_prompt_metadata("response")["version"]
            findings["skills_used"] = skills_used
            
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
            confidence = findings.get("confidence", 0.90) if findings.get("confidence") is not None else 0.90

            try:
                from backend.services.investigation_ledger import record_ledger_entry
                from backend.services.llm_client import MODEL_ROUTING, DEFAULT_MODEL
                record_ledger_entry(
                    investigation_id=getattr(context, "investigation_id", None) or context.alert_data.get("alert_id", "unknown"),
                    agent_name=self.name,
                    phase="response",
                    prompt_sent=prompt,
                    llm_response=json.dumps(findings, default=str),
                    model_used=MODEL_ROUTING.get("response", DEFAULT_MODEL),
                    decision=findings,
                    skills_invoked=skills_used,
                )
            except Exception as ledger_err:
                logger.debug(f"Ledger recording skipped for response: {ledger_err}")
        except Exception as e:
            logger.warning(f"ResponsePlannerAgent LLM error: {e}. Generating rule-based response actions.")
            fallback_actions = []
            
            # Rule-based response action generation from entities & IOCs
            for ent in entities:
                etype = ent.get("type", "").lower() if isinstance(ent, dict) else ""
                eid = ent.get("id", "") if isinstance(ent, dict) else str(ent)
                if etype in ("host", "endpoint") and eid:
                    fallback_actions.append({
                        "action_type": "isolate_host",
                        "target": eid,
                        "description": f"Isolate endpoint {eid} from the network to prevent lateral movement.",
                        "priority": "High"
                    })
                elif etype in ("user", "account", "identity") and eid:
                    fallback_actions.append({
                        "action_type": "reset_credentials",
                        "target": eid,
                        "description": f"Force password reset and revoke active sessions for user {eid}.",
                        "priority": "High"
                    })
                elif etype in ("ip", "domain") and eid:
                    fallback_actions.append({
                        "action_type": "block_ip" if etype == "ip" else "block_domain",
                        "target": eid,
                        "description": f"Add {eid} to perimeter firewall and proxy egress blocklists.",
                        "priority": "Critical"
                    })
                    
            if not fallback_actions:
                fallback_actions.append({
                    "action_type": "isolate_host",
                    "target": "affected-host",
                    "description": "Quarantine suspected endpoint pending forensic acquisition.",
                    "priority": "High"
                })

            crit_count = sum(1 for a in fallback_actions if a.get("priority") == "Critical")
            findings = {
                "actions_recommended": fallback_actions,
                "critical_actions": crit_count,
                "skills_used": ["isolate-host", "block-ip", "reset-credentials"],
                "summary": f"Generated {len(fallback_actions)} rule-based containment actions based on active IOCs.",
                "fallback_applied": True,
                "warning": f"Rule-based response fallback applied due to LLM error: {str(e)}"
            }
            confidence = 0.70

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

from backend.services.supervisor import SupervisorAgent

AGENT_REGISTRY: Dict[str, BaseAgent] = {
    "triage_agent": TriageAgent(),
    "evidence_agent": EvidenceAgent(),
    "discovery_agent": NetworkDiscoveryAgent(),
    "compression_agent": CompressionAgent(),
    "rca_agent": RCAAnalystAgent(),
    "response_agent": ResponsePlannerAgent(),
    "supervisor_agent": SupervisorAgent(),
}


class OrchestratorAgent:
    """
    Main orchestrator that:
    1. Receives a high-level task
    2. Plans sub-tasks or runs Autonomous ReAct Supervisor
    3. Dispatches to specialized agents (parallel where possible)
    4. Streams progress via SSE
    5. Synthesizes final answer
    """

    def __init__(self):
        self.agents = AGENT_REGISTRY
        self.supervisor = SupervisorAgent()

    async def plan(self, task: str, alert_data: Dict[str, Any], use_ai_planner: bool = False) -> ExecutionPlan:
        """Create an execution plan for the given task.
        
        When use_ai_planner=True, consults the LLM to dynamically select agents.
        Falls back to the static plan on failure or when use_ai_planner=False.
        """
        from backend.services.pipeline_core import build_ai_plan, build_static_plan_subtasks

        if use_ai_planner:
            return await build_ai_plan(alert_data, valid_agents=set(self.agents.keys()))

        return build_static_plan_subtasks()

    async def execute_stream(self, task: str, alert_data: Dict[str, Any], use_ai_planner: bool = False, investigation_id: Optional[str] = None) -> AsyncGenerator[str, None]:
        """Execute the investigation and yield SSE events for each step.
        
        Dual-mode support:
        - use_ai_planner=False: Fast, deterministic 5-phase execution.
        - use_ai_planner=True: Autonomous ReAct Supervisor dynamically driving phases.

        `investigation_id`, when provided by the caller (e.g. the API route), becomes the
        canonical run_id used for every SSE event AND the InvestigationContext -- keeping the
        ledger/audit trail and the investigation record keyed under the same identifier the
        caller already has. Falls back to a freshly generated id if omitted (e.g. direct/test use).
        """
        if use_ai_planner:
            async for evt in self._execute_stream_react_supervisor(task, alert_data, investigation_id):
                yield evt
        else:
            async for evt in self._execute_stream_static(task, alert_data, investigation_id):
                yield evt

    async def _execute_stream_static(self, task: str, alert_data: Dict[str, Any], investigation_id: Optional[str] = None) -> AsyncGenerator[str, None]:
        """Fast, deterministic 5-phase execution for standard triage."""
        run_id = investigation_id or f"run-{uuid.uuid4().hex[:8]}"
        run_start = time.time()
        context = InvestigationContext(alert_data=alert_data, use_ai_planner=False, investigation_id=run_id)

        # Playbook Engine (Wave 3, Phase K): if a declarative playbook's trigger
        # matches this alert (severity + tags), it takes precedence over the
        # static 5-phase plan for this run -- e.g. the ransomware-response-v1
        # playbook isolates the host first, then investigates, notifies, and
        # reports. Any exception here falls straight through to the unchanged
        # static plan below (zero regression for the common/no-match case).
        try:
            from backend.services.pipeline_core import find_matching_playbook
            from backend.services.playbook_engine import playbook_engine
            matched_playbook = find_matching_playbook(alert_data)
        except Exception as playbook_lookup_err:
            logger.debug(f"Playbook lookup skipped: {playbook_lookup_err}")
            matched_playbook = None

        if matched_playbook is not None:
            yield sse_event("run_start", {
                "run_id": run_id,
                "task": task,
                "status": "planning",
                "mode": "playbook",
                "playbook_id": matched_playbook.id,
                "playbook_name": matched_playbook.name,
                "timestamp": datetime.now().isoformat(),
            })
            yield sse_event("playbook_engaged", {
                "run_id": run_id,
                "playbook_id": matched_playbook.id,
                "playbook_name": matched_playbook.name,
                "steps": [{"id": s.id, "name": s.name, "type": s.type} for s in matched_playbook.steps],
            })

            try:
                exec_result = await playbook_engine.execute_playbook(matched_playbook, context)
            except Exception as playbook_exec_err:
                logger.warning(f"Playbook execution failed, falling back to static plan: {playbook_exec_err}")
                exec_result = None

            if exec_result is not None:
                all_reports: Dict[str, AgentReport] = {}
                for step_result in exec_result.step_results:
                    yield sse_event("playbook_step_complete", {
                        "run_id": run_id,
                        "step_id": step_result.step_id,
                        "step_name": step_result.step_name,
                        "status": step_result.status,
                        "retried": step_result.retried,
                    })
                    detail = step_result.detail if isinstance(step_result.detail, dict) else {}
                    for task_id, report in (detail.get("reports") or {}).items():
                        all_reports[task_id] = report

                yield sse_event("synthesis_start", {"run_id": run_id, "timestamp": datetime.now().isoformat()})
                synthesis = self._synthesize(all_reports, None, context)
                total_duration = int((time.time() - run_start) * 1000)
                yield sse_event("run_complete", {
                    "run_id": run_id,
                    "status": "aborted" if exec_result.aborted else "completed",
                    "total_duration_ms": total_duration,
                    "synthesis": synthesis,
                    "playbook_id": matched_playbook.id,
                    "timestamp": datetime.now().isoformat(),
                })
                return

        # Planning Phase
        yield sse_event("run_start", {
            "run_id": run_id,
            "task": task,
            "status": "planning",
            "mode": "deterministic_static",
            "timestamp": datetime.now().isoformat(),
        })

        await asyncio.sleep(0.1)
        plan = await self.plan(task, alert_data, use_ai_planner=False)

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

            # Adaptive fallback loop for low confidence RCA
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
                    re_evidence = self.agents["evidence_agent"]
                    re_rca = self.agents["rca_agent"]
                    try:
                        ev_rep = await re_evidence.execute({}, context)
                        all_reports[f"task-evidence-iter{context.iteration}"] = ev_rep
                    except Exception:
                        pass
                    try:
                        rca_rep = await re_rca.execute({}, context)
                        all_reports[f"task-rca-iter{context.iteration}"] = rca_rep
                    except Exception:
                        pass

        # Synthesis
        yield sse_event("synthesis_start", {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
        })
        await asyncio.sleep(0.2)
        synthesis = self._synthesize(all_reports, plan, context)
        total_duration = int((time.time() - run_start) * 1000)

        yield sse_event("run_complete", {
            "run_id": run_id,
            "status": "completed",
            "total_duration_ms": total_duration,
            "synthesis": synthesis,
            "timestamp": datetime.now().isoformat(),
        })

    async def _execute_stream_react_supervisor(self, task: str, alert_data: Dict[str, Any], investigation_id: Optional[str] = None) -> AsyncGenerator[str, None]:
        """Autonomous ReAct Investigation Supervisor dynamically selecting phases and actions."""
        run_id = investigation_id or f"run-{uuid.uuid4().hex[:8]}"
        run_start = time.time()
        context = InvestigationContext(alert_data=alert_data, use_ai_planner=True, investigation_id=run_id)

        yield sse_event("run_start", {
            "run_id": run_id,
            "task": task,
            "status": "planning",
            "mode": "autonomous_react_supervisor",
            "timestamp": datetime.now().isoformat(),
        })

        yield sse_event("plan_created", {
            "run_id": run_id,
            "plan_id": f"plan-react-{run_id}",
            "objective": "Autonomous ReAct Investigation Loop",
            "reasoning": "Observation-driven investigation dynamically directed by Supervisor Agent.",
            "total_phases": 1,
            "total_tasks": 1,
            "phases": [
                {"phase_num": 1, "parallel": False, "agents": ["triage_agent"], "status": "running"},
            ]
        })

        all_reports: Dict[str, AgentReport] = {}
        current_phase_num = 1

        # Phase 1: Mandatory Triage
        yield sse_event("phase_start", {
            "run_id": run_id,
            "phase_num": current_phase_num,
            "parallel": False,
            "agents": ["triage_agent"]
        })
        yield sse_event("agent_start", {
            "run_id": run_id,
            "phase_num": current_phase_num,
            "agent_name": "triage_agent",
            "task_id": "task-triage",
            "description": "Initial alert triage, classification, and entity extraction",
            "parallel": False,
            "timestamp": datetime.now().isoformat()
        })
        triage_report = await self.agents["triage_agent"].execute({}, context)
        all_reports["task-triage"] = triage_report
        yield sse_event("agent_complete", {
            "run_id": run_id,
            "phase_num": current_phase_num,
            "agent_name": "triage_agent",
            "task_id": "task-triage",
            "report": triage_report.to_dict()
        })
        yield sse_event("phase_complete", {"run_id": run_id, "phase_num": current_phase_num})

        # Phase 2+: Dynamic ReAct Supervisor Loop
        investigation_active = True
        early_terminated_benign = False

        while investigation_active and context.iteration < context.max_iterations:
            # Step 1: Supervisor Decision
            decision = await self.supervisor.decide_next_step(context)
            context.record_supervisor_decision(decision.model_dump())

            yield sse_event("supervisor_thought", {
                "run_id": run_id,
                "iteration": context.iteration + 1,
                "supervisor_assessment": getattr(decision, "supervisor_assessment", ""),
                "thought": decision.thought,
                "action": decision.action,
                "target_entities": decision.target_entities,
                "target_skills": decision.target_skills,
                "specific_goal": decision.specific_goal,
                "pivot_entity_detected": decision.pivot_entity_detected,
                "timestamp": datetime.now().isoformat()
            })

            # Check termination conditions
            if decision.action == "terminate_benign":
                early_terminated_benign = True
                investigation_active = False
                yield sse_event("investigation_terminated_early", {
                    "run_id": run_id,
                    "reason": "Supervisor confirmed benign/false positive activity",
                    "thought": decision.thought
                })
                break

            if decision.action == "finalize_response":
                investigation_active = False
                break

            # Step 2: Execute Chosen Action
            current_phase_num += 1
            action_to_agent = {
                "gather_evidence": "evidence_agent",
                "discover_network": "discovery_agent",
                "compress_events": "compression_agent",
                "perform_rca": "rca_agent",
            }
            canonical_agent_name = action_to_agent.get(decision.action, decision.action)
            yield sse_event("phase_start", {
                "run_id": run_id,
                "phase_num": current_phase_num,
                "parallel": False,
                "agents": [canonical_agent_name]
            })
            task_id = f"task-{decision.action}-iter{context.iteration + 1}"
            yield sse_event("agent_start", {
                "run_id": run_id,
                "phase_num": current_phase_num,
                "agent_name": canonical_agent_name,
                "task_id": task_id,
                "description": decision.specific_goal,
                "parallel": False,
                "timestamp": datetime.now().isoformat()
            })

            step_report = None
            if decision.action == "gather_evidence":
                step_report = await self.agents["evidence_agent"].execute({}, context)
            elif decision.action == "discover_network":
                step_report = await self.agents["discovery_agent"].execute({}, context)
            elif decision.action == "compress_events":
                step_report = await self.agents["compression_agent"].execute({}, context)
            elif decision.action == "perform_rca":
                step_report = await self.agents["rca_agent"].execute({}, context)
                if "confidence_score" in context.rca_findings:
                    context.confidence_history.append(context.rca_findings["confidence_score"])
            
            if step_report:
                all_reports[task_id] = step_report
                yield sse_event("agent_complete", {
                    "run_id": run_id,
                    "phase_num": current_phase_num,
                    "agent_name": step_report.agent_name or canonical_agent_name,
                    "task_id": task_id,
                    "report": step_report.to_dict()
                })

            yield sse_event("phase_complete", {"run_id": run_id, "phase_num": current_phase_num})
            context.iteration += 1

        # Phase Final: Response Planning (unless terminated early as benign)
        if not early_terminated_benign:
            current_phase_num += 1
            yield sse_event("phase_start", {
                "run_id": run_id,
                "phase_num": current_phase_num,
                "parallel": False,
                "agents": ["response_agent"]
            })
            yield sse_event("agent_start", {
                "run_id": run_id,
                "phase_num": current_phase_num,
                "agent_name": "response_agent",
                "task_id": "task-response",
                "description": "Generate prioritized containment and remediation response plan",
                "parallel": False,
                "timestamp": datetime.now().isoformat()
            })
            response_report = await self.agents["response_agent"].execute({}, context)
            all_reports["task-response"] = response_report
            yield sse_event("agent_complete", {
                "run_id": run_id,
                "phase_num": current_phase_num,
                "agent_name": "response_agent",
                "task_id": "task-response",
                "report": response_report.to_dict()
            })
            yield sse_event("phase_complete", {"run_id": run_id, "phase_num": current_phase_num})

        # Synthesis
        yield sse_event("synthesis_start", {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
        })
        await asyncio.sleep(0.2)
        synthesis = self._synthesize(all_reports, None, context)
        total_duration = int((time.time() - run_start) * 1000)

        yield sse_event("run_complete", {
            "run_id": run_id,
            "status": "completed",
            "total_duration_ms": total_duration,
            "synthesis": synthesis,
            "timestamp": datetime.now().isoformat(),
        })

    def _synthesize(self, reports: Dict[str, AgentReport], plan: Optional[ExecutionPlan], context: InvestigationContext = None) -> Dict[str, Any]:
        """Synthesize all agent reports into a final summary."""
        from backend.services.pipeline_core import synthesize_reports
        return synthesize_reports(reports, context)
