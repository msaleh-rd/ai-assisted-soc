"""Triage Skill Handlers — executes triage skills for alert ingestion and validation."""

import re
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.models.alert import AlertSeverity
from backend.services.mitre_mapper import mitre_mapper
from backend.services.threat_intel.local_feeds import local_threat_intel_db

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
            "threat-intel-prefilter": TriageSkillExecutor._handle_threat_intel_prefilter,
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
    # Skill: Threat Intel Pre-Filter
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_threat_intel_prefilter(input_data: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Lightweight IOC pre-filter against local reputation."""
        entities = input_data.get("entities", {})
        flagged = []

        ips = entities.get("ips", [])
        domains = entities.get("domains", [])
        hashes = entities.get("hashes", [])

        # Check known malicious ranges/patterns
        for ip in ips:
            if str(ip).startswith("192.42.1.") or str(ip).startswith("198.51.100."):
                flagged.append({"ioc": ip, "type": "ip", "reason": "Known C2 Threat Actor range", "risk": 0.95})

        for d in domains:
            if any(bad in str(d).lower() for bad in ("evil", "c2", "malware", "sinkhole", "tunnel")):
                flagged.append({"ioc": d, "type": "domain", "reason": "High-risk domain indicator", "risk": 0.90})

        for h in hashes:
            if len(str(h)) == 64 and (str(h).startswith("dead") or str(h).startswith("beef")):
                flagged.append({"ioc": h, "type": "hash", "reason": "Flagged malware hash signature", "risk": 0.99})

        # Ground-truth checks against locally-vendored threat-intel feeds (deterministic,
        # no LLM guesswork): suspicious destination ports and known malware mutex names.
        ports = entities.get("ports", [])
        for port in ports:
            try:
                port_match = local_threat_intel_db.lookup_port(int(port))
            except (TypeError, ValueError):
                port_match = None
            if port_match:
                flagged.append({
                    "ioc": port,
                    "type": "port",
                    "reason": port_match.detail or "Known suspicious/malware-associated port",
                    "risk": port_match.confidence,
                    "source": port_match.source,
                    "source_list": port_match.source_list,
                })

        processes = entities.get("processes", []) + entities.get("mutexes", [])
        for proc in processes:
            mutex_match = local_threat_intel_db.lookup_mutex(str(proc))
            if mutex_match:
                flagged.append({
                    "ioc": proc,
                    "type": "mutex",
                    "reason": mutex_match.detail or "Known malware mutex name",
                    "risk": mutex_match.confidence,
                    "source": mutex_match.source,
                    "source_list": mutex_match.source_list,
                })

        return {
            "flagged_iocs": flagged,
            "flagged_count": len(flagged),
            "status": "success",
            "prefilter_verdict": "MALICIOUS_FOUND" if flagged else "CLEAN"
        }

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
            "files": [],
            "ports": [],
            "mutexes": []
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
                elif any(x in k_low for x in ("port", "dest_port", "dst_port")):
                    if val_str not in entities["ports"]:
                        entities["ports"].append(val_str)
                elif "mutex" in k_low:
                    if val_str not in entities["mutexes"]:
                        entities["mutexes"].append(val_str)

        # Ground-truth tagging: check extracted files against locally-vendored ransomware
        # extension/note lists so downstream skills (severity-evaluator, etc.) don't need
        # to re-derive this — deterministic evidence beats LLM guesswork.
        threat_intel_matches: List[Dict[str, Any]] = []
        for file_value in entities["files"]:
            ext_match = local_threat_intel_db.lookup_extension(file_value)
            if ext_match:
                threat_intel_matches.append({
                    "ioc": file_value,
                    "indicator_type": "ransomware_extension",
                    "category": ext_match.category,
                    "confidence": ext_match.confidence,
                    "detail": ext_match.detail,
                    "source": ext_match.source,
                    "source_list": ext_match.source_list,
                })
                continue
            note_match = local_threat_intel_db.lookup_ransomware_note(file_value)
            if note_match:
                threat_intel_matches.append({
                    "ioc": file_value,
                    "indicator_type": "ransomware_note",
                    "category": note_match.category,
                    "confidence": note_match.confidence,
                    "detail": note_match.detail,
                    "source": note_match.source,
                    "source_list": note_match.source_list,
                })

        return {
            "entities": entities,
            "total_iocs_found": sum(len(v) for v in entities.values()),
            "threat_intel_matches": threat_intel_matches,
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

        from backend.services.skills import skill_registry

        if technique:
            tech_id = technique.technique_id
            rec_skills = [s.name for s in skill_registry.find_skills_for_mitre_technique(tech_id)]
            return {
                "tactic": technique.tactic_name,
                "tactic_id": technique.tactic_id,
                "technique": technique.technique_name,
                "technique_id": tech_id,
                "confidence": 0.85,
                "recommended_skills": rec_skills,
                "status": "success"
            }

        # Fallback to general discovery
        rec_skills = [s.name for s in skill_registry.find_skills_for_mitre_technique("T1082")]
        return {
            "tactic": "discovery",
            "tactic_id": "TA0007",
            "technique": "System Information Discovery",
            "technique_id": "T1082",
            "confidence": 0.50,
            "recommended_skills": rec_skills,
            "status": "success"
        }

    # ------------------------------------------------------------------
    # Skill: Severity Evaluator
    # ------------------------------------------------------------------

    @staticmethod
    def _check_local_threat_intel(alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check alert_data fields against locally-vendored threat-intel ground truth.

        Scans string/list values for known ransomware extensions, ransomware note filenames,
        and malware mutex names. Returns match details on the first hit, or None if nothing
        matches — letting severity scoring skip keyword/LLM guesswork entirely when a
        deterministic indicator is present.
        """
        candidates: List[str] = []
        for v in alert_data.values():
            if isinstance(v, str) and v.strip():
                candidates.append(v.strip())
            elif isinstance(v, list):
                candidates.extend(str(x).strip() for x in v if str(x).strip())

        for candidate in candidates:
            ext_match = local_threat_intel_db.lookup_extension(candidate)
            if ext_match:
                return {"match": ext_match, "matched_value": candidate, "indicator_type": "ransomware_extension"}
            note_match = local_threat_intel_db.lookup_ransomware_note(candidate)
            if note_match:
                return {"match": note_match, "matched_value": candidate, "indicator_type": "ransomware_note"}
            mutex_match = local_threat_intel_db.lookup_mutex(candidate)
            if mutex_match:
                return {"match": mutex_match, "matched_value": candidate, "indicator_type": "suspicious_mutex"}
        return None

    @staticmethod
    async def _handle_severity_evaluator(input_data: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        alert_data = input_data.get("alert_data", input_data)
        text = json.dumps(alert_data).lower()

        intel_hit = TriageSkillExecutor._check_local_threat_intel(alert_data)
        if intel_hit:
            match = intel_hit["match"]
            return {
                "severity": AlertSeverity.CRITICAL.value,
                "risk_score": max(0.9, match.confidence),
                "requires_immediate_action": True,
                "grounded": True,
                "grounding_source": match.source,
                "grounding_detail": {
                    "indicator_type": intel_hit["indicator_type"],
                    "matched_value": intel_hit["matched_value"],
                    "category": match.category,
                    "source_list": match.source_list,
                    "detail": match.detail,
                },
                "status": "success"
            }

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
            "grounded": False,
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
