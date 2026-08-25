"""Autonomous ReAct Investigation Supervisor.

Dynamically drives the investigation process by observing the current investigation
blackboard, reasoning about forensic gaps and pivot leads, and selecting the next optimal
action from the capability catalog.
"""

import json
import logging
from typing import Dict, Any, List, Optional

from backend.services.investigation_context import InvestigationContext
from backend.services.llm_client import get_llm, SupervisorDecision
from backend.services.prompt_manager import prompt_manager

logger = logging.getLogger("supervisor")


class SupervisorAgent:
    """ReAct Investigation Supervisor for AI-driven autonomous investigations."""

    def __init__(self):
        self.name = "supervisor_agent"

    async def decide_next_step(self, context: InvestigationContext) -> SupervisorDecision:
        """Analyze the current investigation context and decide the next single action.
        
        Args:
            context: Shared investigation blackboard containing current entities, evidence,
                     compressed timeline, messages, and RCA findings.
                     
        Returns:
            SupervisorDecision containing thought, action, target_entities, target_skills, and goal.
        """
        # 1. Prepare structured summary strings for the supervisor prompt
        alert = context.alert_data or {}
        alert_summary = (
            f"Alert ID: {alert.get('alert_id', 'unknown')} | "
            f"Host: {alert.get('computer_name', 'unknown')} | "
            f"User: {alert.get('user_name', 'unknown')} | "
            f"Description: {alert.get('description', 'No description provided')}"
        )

        entities_list = [
            f"- [{e.get('type', 'unknown')}] {e.get('id', '')}"
            for e in context.entities
            if isinstance(e, dict) and e.get("id")
        ]
        if context.pivot_entities:
            entities_list.append("\nPivot Entities Discovered in Logs:")
            for pe in context.pivot_entities:
                entities_list.append(f"  * [PIVOT {pe.get('type', 'unknown')}] {pe.get('id', '')}")
        entities_json = "\n".join(entities_list) if entities_list else "No entities registered yet."

        # Summarize latest compressed timeline milestones
        timeline = context.compressed_events.get("timeline", [])
        if timeline:
            timeline_items = [
                f"- [{evt.get('timestamp', '')}] ({evt.get('entity', '')}) {evt.get('action', '')} [Risk: {evt.get('risk_score', 0.0)}]"
                for evt in timeline[:8]
            ]
            timeline_summary = "\n".join(timeline_items)
        else:
            timeline_summary = "No compressed timeline generated yet (0 events)."

        # Current RCA status
        rca = context.rca_findings or {}
        current_root_cause = rca.get("root_cause", "Not yet determined")
        current_confidence = rca.get("confidence_score", 0.0)

        # Pending messages / gaps
        gaps_list = []
        for msg in context.messages:
            if not msg.resolved:
                gaps_list.append(f"- [{msg.msg_type} from {msg.source_agent}]: {json.dumps(msg.payload)}")
        identified_gaps = "\n".join(gaps_list) if gaps_list else "No unresolved gap messages."

        # History of supervisor steps
        history_items = []
        for h in context.supervisor_history:
            history_items.append(
                f"- Step {h.get('iteration', 0)}: Action '{h.get('action')}' on {h.get('target_entities', [])} -> Goal: {h.get('specific_goal', '')}"
            )
        history_json = "\n".join(history_items) if history_items else "No previous supervisor actions."

        # 2. Invoke Supervisor LLM with structured output
        try:
            llm = get_llm(role="supervisor")
            structured_llm = llm.with_structured_output(SupervisorDecision)

            system_prompt = prompt_manager.get_system_prompt("supervisor")
            user_prompt = prompt_manager.build_user_prompt(
                "supervisor",
                alert_summary=alert_summary,
                classification=context.classification,
                severity=context.severity,
                iteration=context.iteration + 1,
                max_iterations=context.max_iterations,
                entities_json=entities_json,
                timeline_summary=timeline_summary,
                current_root_cause=current_root_cause,
                current_confidence=current_confidence,
                identified_gaps=identified_gaps,
                history_json=history_json,
                action_counts_json=json.dumps(context.action_counts, indent=2),
                max_action_iterations=context.max_action_iterations
            )

            prompt = f"{system_prompt}\n\n{user_prompt}"
            decision: SupervisorDecision = await structured_llm.ainvoke(prompt)

            # Auto-register newly detected pivot entity if provided
            if decision.pivot_entity_detected:
                sanitized_entity = self._sanitize_entity_id(decision.pivot_entity_detected)
                if sanitized_entity:
                    # Infer type
                    ptype = "ip" if any(c.isdigit() for c in sanitized_entity) and "." in sanitized_entity else "host"
                    context.add_entity(sanitized_entity, entity_type=ptype, is_pivot=True)
                    logger.info(f"Supervisor registered new lateral pivot entity: {sanitized_entity} ({ptype})")

            # Validate decision
            decision = self._validate_and_sanitize_decision(decision, context)
            logger.info(f"Supervisor Decision (Iteration {context.iteration + 1}): {decision.action} on {decision.target_entities} | Goal: {decision.specific_goal}")
            return decision

        except Exception as e:
            logger.warning(f"Supervisor LLM decision error: {e}, applying heuristic fallback decision")
            return self._heuristic_fallback_decision(context)

    def _sanitize_entity_id(self, entity_str: str) -> str:
        """Extracts purely the IP, domain, or filename from conversational text."""
        import re
        if not entity_str:
            return ""
        # try to find IP
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', entity_str)
        if ip_match:
            return ip_match.group(0)
        # fallback string cleanup, remove quotes, etc.
        cleaned = re.sub(r'["\']', '', entity_str)
        
        # Check against common negative words from LLM conversational outputs
        clean_strip = cleaned.strip()
        if clean_strip.lower() in ["no", "none", "unknown", "n/a", "null", "false", "nothing"]:
            return ""

        # If it's a short string, just return it
        if len(cleaned.split()) <= 2:
            return cleaned.strip()
        # otherwise try to find something that looks like an entity (filename/hostname)
        for word in cleaned.split():
            word = word.strip(',.')
            if '.' in word or '\\' in word or '/' in word:
                return word
        return cleaned.split()[0] if cleaned else ""

    def _validate_and_sanitize_decision(self, decision: SupervisorDecision, context: InvestigationContext) -> SupervisorDecision:
        """Ensure the chosen action is executable and targets valid entities."""
        all_entity_ids = {e.get("id") for e in context.entities if isinstance(e, dict) and e.get("id")}
        
        # If gather_evidence has no target entities, supply all known entities
        if decision.action == "gather_evidence" and not decision.target_entities:
            decision.target_entities = list(all_entity_ids)

        # If discover_network has no targets, filter IP entities
        if decision.action == "discover_network" and not decision.target_entities:
            ip_entities = [e.get("id") for e in context.entities if isinstance(e, dict) and e.get("type") == "ip"]
            decision.target_entities = ip_entities or list(all_entity_ids)

        # If RCA is requested but no timeline exists, do compression first
        if decision.action == "perform_rca" and not context.compressed_events:
            decision.action = "compress_events"
            decision.specific_goal = "Generate compressed timeline milestones before performing RCA"

        # If finalize_response is selected but RCA hasn't run yet, run RCA first
        if decision.action == "finalize_response" and not context.rca_findings:
            decision.action = "perform_rca"
            decision.specific_goal = "Synthesize root cause and attack chain before finalizing response"

        # Enforce per-action limits
        if context.action_counts.get(decision.action, 0) >= context.max_action_iterations:
            logger.warning(f"Supervisor chose {decision.action} but it has reached the max limit of {context.max_action_iterations}. Forcing fallback.")
            decision = self._heuristic_fallback_decision(context)

        return decision

    def _heuristic_fallback_decision(self, context: InvestigationContext) -> SupervisorDecision:
        """Deterministic fallback decision if the LLM fails or is unavailable."""
        # Find next available action
        if not context.entity_graph and context.action_counts.get("gather_evidence", 0) < context.max_action_iterations:
            all_ids = [e.get("id") for e in context.entities if isinstance(e, dict) and e.get("id")]
            return SupervisorDecision(
                thought="No entity graph collected yet. Running evidence collection on all triage entities.",
                action="gather_evidence",
                target_entities=all_ids,
                specific_goal="Gather baseline evidence for triage entities"
            )
        
        if not context.compressed_events and context.action_counts.get("compress_events", 0) < context.max_action_iterations:
            return SupervisorDecision(
                thought="Evidence collected but timeline not compressed yet. Running 7-stage compression pipeline.",
                action="compress_events",
                specific_goal="Compress collected raw evidence into high-signal timeline"
            )
            
        if (not context.rca_findings or context.rca_findings.get("confidence_score", 0.0) < 0.70) and context.action_counts.get("perform_rca", 0) < context.max_action_iterations:
            return SupervisorDecision(
                thought="Timeline is ready. Performing Root Cause Analysis and attack chain reconstruction.",
                action="perform_rca",
                specific_goal="Reconstruct attack chain and score causal confidence"
            )
            
        return SupervisorDecision(
            thought="Investigation complete or all phases maxed out. Finalizing response plan and containment actions.",
            action="finalize_response",
            specific_goal="Generate prioritized containment and remediation response plan"
        )
