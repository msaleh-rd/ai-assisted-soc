"""Triage Skill Handlers — executes triage skills for alert ingestion and validation."""

import re
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.models.alert import AlertSeverity
from backend.services.mitre_mapper import mitre_mapper

logger = logging.getLogger("triage-skills")


class TriageSkillExecutor:
    """Dispatches and executes triage skills."""

    @staticmethod
    async def execute_skill(
        skill_name: str,
        input_data: Dict[str, Any],
        context_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a specific triage skill."""
        handler_map = {
            "ioc-extractor": TriageSkillExecutor._handle_ioc_extractor,
            "mitre-classifier": TriageSkillExecutor._handle_mitre_classifier,
            "severity-evaluator": TriageSkillExecutor._handle_severity_evaluator,
            "grounding-validator": TriageSkillExecutor._handle_grounding_validator,
        }

        handler = handler_map.get(skill_name)
        if not handler:
            logger.warning(f"No specific handler for triage skill {skill_name}")
            return {"status": "error", "message": f"Skill {skill_name} not found"}

        try:
            return await handler(input_data, context_data or {})
        except Exception as e:
            logger.error(f"Error executing triage skill {skill_name}: {e}")
            return {"status": "error", "error": str(e)}

    # ------------------------------------------------------------------
    # Skill: IOC Extractor
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_ioc_extractor(input_data: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        raw_alert = input_data.get("raw_alert", input_data)
        text_content = json.dumps(raw_alert) if isinstance(raw_alert, (dict, list)) else str(raw_alert)

        # Regex patterns for IOC extraction
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        hash_pattern = r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{32})\b'

        ips = set(re.findall(ip_pattern, text_content))
        domains = set(re.findall(domain_pattern, text_content))
        hashes = set(re.findall(hash_pattern, text_content))

        # Filter internal/noise domains
        domains = {d for d in domains if not d.endswith(".py") and not d.endswith(".json") and not d.endswith(".txt")}

        # Specific entity fields from structured alert
        entities: Dict[str, Any] = {
            "ips": sorted(list(ips)),
            "domains": sorted(list(domains)),
            "hashes": sorted(list(hashes)),
            "users": [],
            "hosts": [],
            "processes": [],
            "files": []
        }

        if isinstance(raw_alert, dict):
            for k, v in raw_alert.items():
                k_low = k.lower()
                val_str = str(v).strip()
                if not val_str or val_str == "None":
                    continue

                if any(x in k_low for x in ("user", "username", "account", "uid")):
                    if val_str not in entities["users"]:
                        entities["users"].append(val_str)
                elif any(x in k_low for x in ("host", "hostname", "computer_name", "endpoint")):
                    if val_str not in entities["hosts"]:
                        entities["hosts"].append(val_str)
                elif any(x in k_low for x in ("process", "proc_name", "command_line", "exec")):
                    if val_str not in entities["processes"]:
                        entities["processes"].append(val_str)
                elif any(x in k_low for x in ("file", "filename", "file_name", "file_path")):
                    if val_str not in entities["files"]:
                        entities["files"].append(val_str)

        return {
            "entities": entities,
            "total_iocs_found": sum(len(v) for v in entities.values()),
            "status": "success"
        }

    # ------------------------------------------------------------------
    # Skill: MITRE Classifier
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_mitre_classifier(input_data: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        alert_data = input_data.get("alert_data", input_data)
        event_text = f"{alert_data.get('alert_name', '')} {alert_data.get('alert_description', '')} {alert_data.get('event_type', '')}"
        
        technique = mitre_mapper.classify_event(event_text, metadata=alert_data)

        if technique:
            return {
                "tactic": technique.tactic_name,
                "tactic_id": technique.tactic_id,
                "technique": technique.name,
                "technique_id": technique.technique_id,
                "confidence": 0.85,
                "status": "success"
            }

        # Fallback to general discovery
        return {
            "tactic": "discovery",
            "tactic_id": "TA0007",
            "technique": "System Information Discovery",
            "technique_id": "T1082",
            "confidence": 0.50,
            "status": "success"
        }

    # ------------------------------------------------------------------
    # Skill: Severity Evaluator
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_severity_evaluator(input_data: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        alert_data = input_data.get("alert_data", input_data)
        text = json.dumps(alert_data).lower()

        if any(k in text for k in ("ransom", "donotcry", "wannacry", "encrypt", "domain admin", "c2 beacon")):
            severity = AlertSeverity.CRITICAL
            score = 0.95
            requires_immediate_action = True
        elif any(k in text for k in ("mimikatz", "privilege_escalation", "sudo", "execve", "malware")):
            severity = AlertSeverity.HIGH
            score = 0.80
            requires_immediate_action = True
        elif any(k in text for k in ("failed login", "scan", "probing", "suspicious")):
            severity = AlertSeverity.MEDIUM
            score = 0.50
            requires_immediate_action = False
        else:
            severity = AlertSeverity.LOW
            score = 0.20
            requires_immediate_action = False

        return {
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "risk_score": score,
            "requires_immediate_action": requires_immediate_action,
            "status": "success"
        }

    # ------------------------------------------------------------------
    # Skill: Grounding Validator
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_grounding_validator(input_data: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        extracted = input_data.get("extracted_entities", [])
        raw_text = str(input_data.get("raw_alert_text", "")).lower()

        validated = []
        dropped = []

        for entity in extracted:
            ent_val = str(entity.get("value") if isinstance(entity, dict) else entity).strip()
            if ent_val.lower() in raw_text:
                validated.append(entity)
            else:
                dropped.append(entity)

        hallucination_rate = len(dropped) / max(len(extracted), 1)
        confidence = round(1.0 - hallucination_rate, 2)

        return {
            "validated_entities": validated,
            "dropped_entities": dropped,
            "hallucination_rate": hallucination_rate,
            "confidence_score": confidence,
            "status": "success"
        }
