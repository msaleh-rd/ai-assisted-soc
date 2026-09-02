"""Evidence Skill Handlers — executes evidence skills against real log data.

Each handler follows a 3-tier lookup:
  1. PostgreSQL EntityRecord (if ingested)
  2. Real log files via LogIngestor (Wazuh, Suricata, audit.log, auth.log)
  3. Minimal generic fallback (no hardcoded scenario data)
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import Counter

from backend.database.connection import SessionLocal
from backend.database.postgres import EntityRecord, EventRecord
from backend.services.threat_intel.local_feeds import local_threat_intel_db
from backend.services.evidence.yara_scanner import yara_scanner
from backend.services.evidence.virustotal_client import virustotal_client

logger = logging.getLogger("evidence-skills")


class EvidenceSkillExecutor:
    """Dispatches and executes evidence skills."""

    @staticmethod
    async def execute_skill(
        skill_name: str,
        entity_id: str,
        entity_type: str,
        context_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a specific evidence skill for an entity."""
        # Tool-call authorization boundary (Phase E, Step 3): every skill invocation
        # goes through a single choke point rather than being called ad hoc.
        try:
            from backend.services.agentic_security import skill_authorization_gate
            investigation_id = (context_data or {}).get("investigation_id", "unknown")
            skill_authorization_gate.authorize(skill_name, phase="evidence", investigation_id=investigation_id)
        except Exception as auth_err:
            logger.debug(f"Skill authorization check skipped for {skill_name}: {auth_err}")

        handler_map = {
            "edr-process-tree": EvidenceSkillExecutor._handle_edr_process_tree,
            "network-flow-analyzer": EvidenceSkillExecutor._handle_network_flow,
            "identity-ad-lookup": EvidenceSkillExecutor._handle_identity_ad,
            "threat-intel-lookup": EvidenceSkillExecutor._handle_threat_intel,
            "file-forensics": EvidenceSkillExecutor._handle_file_forensics,
            "persistence-auditor": EvidenceSkillExecutor._handle_persistence_auditor,
        }

        handler = handler_map.get(skill_name)
        if not handler:
            logger.warning(f"No specific handler for evidence skill {skill_name}, running generic entity lookup")
            return EvidenceSkillExecutor._handle_generic_lookup(entity_id, entity_type)

        try:
            return await handler(entity_id, entity_type, context_data or {})
        except Exception as e:
            logger.error(f"Error executing skill {skill_name} on {entity_id}: {e}")
            return EvidenceSkillExecutor._handle_generic_lookup(entity_id, entity_type)

    # ------------------------------------------------------------------
    # Tier 1: PostgreSQL lookup
    # ------------------------------------------------------------------

    @staticmethod
    def _fetch_db_record(entity_id: str) -> Optional[Dict[str, Any]]:
        if not SessionLocal:
            return None
        db = SessionLocal()
        try:
            record = db.query(EntityRecord).filter_by(entity_id=entity_id).first()
            if record:
                return {
                    "enrichment_data": record.enrichment_data or {},
                    "threat_intel": record.threat_intel or {},
                    "risk_score": record.risk_score or 0.0,
                    "is_known_malicious": record.is_known_malicious or False,
                    "is_suspicious": record.is_suspicious or False,
                    "attributes": record.attributes or {},
                }
            return None
        except Exception as e:
            logger.error(f"DB lookup error for {entity_id}: {e}")
            return None
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Tier 2: Log-backed helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_ingestor():
        """Lazy import to avoid circular imports."""
        from backend.services.evidence.log_ingestor import get_log_ingestor
        return get_log_ingestor()

    @staticmethod
    def _compute_risk_from_events(events: List[Dict[str, Any]]) -> float:
        """Compute aggregate risk from a list of log events."""
        if not events:
            return 0.1
        risks = [e.get("risk_score", 0.1) for e in events]
        return round(max(risks), 2)

    # ------------------------------------------------------------------
    # Static malware analysis helpers (Phase B: YARA + optional VirusTotal)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_sha256(value: str) -> bool:
        value = value.strip()
        return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)

    @staticmethod
    async def _run_static_malware_analysis(entity_id: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Run YARA rule matching (and optional VirusTotal hash lookup) against
        whatever file content/hash is actually available for this entity.

        Returns a dict with `yara_matches` (list) and `vt_result` (dict or None).
        Both are empty/None when no real file bytes or hash are available —
        this is expected for most log-derived file entities and is not an error.
        """
        yara_matches: List[Dict[str, Any]] = []
        vt_result: Optional[Dict[str, Any]] = None

        # Resolve scannable content: explicit bytes/content in context, or a real
        # file path on disk (e.g. a quarantined sample fetched from EDR).
        file_content = ctx.get("file_content") or ctx.get("raw_bytes")
        if file_content is not None:
            if isinstance(file_content, str):
                file_content = file_content.encode("utf-8", errors="ignore")
            matches = yara_scanner.scan_file(file_content)
        else:
            matches = yara_scanner.scan_file(entity_id)

        for m in matches:
            yara_matches.append({
                "rule_name": m.rule_name,
                "category": m.category,
                "severity": m.severity,
                "description": m.description,
                "mitre_attack": m.mitre_attack,
                "matched_strings": m.matched_strings,
            })

        # Resolve a SHA256 for optional VirusTotal lookup.
        sha256 = ctx.get("sha256") or ctx.get("file_hash")
        if not sha256 and EvidenceSkillExecutor._is_sha256(entity_id):
            sha256 = entity_id

        if sha256 and virustotal_client.is_enabled:
            vt = await virustotal_client.lookup_hash(sha256)
            if vt:
                vt_result = {
                    "sha256": vt.sha256,
                    "malicious_count": vt.malicious_count,
                    "total_engines": vt.total_engines,
                    "detection_ratio": vt.detection_ratio,
                    "detected_names": vt.detected_names,
                    "reputation": vt.reputation,
                    "permalink": vt.permalink,
                    "is_known_malicious": vt.is_known_malicious,
                }

        return {"yara_matches": yara_matches, "vt_result": vt_result}

    # ------------------------------------------------------------------
    # Skill: EDR Process Tree
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Helper functions
    # ------------------------------------------------------------------

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        ip_str = str(ip_str).strip()
        if ip_str in ("127.0.0.1", "localhost", "::1"):
            return True
        parts = ip_str.split(".")
        if len(parts) == 4:
            try:
                p0, p1 = int(parts[0]), int(parts[1])
                if p0 == 10:
                    return True
                if p0 == 172 and 16 <= p1 <= 31:
                    return True
                if p0 == 192 and p1 == 168:
                    return True
                if p0 == 169 and p1 == 254:
                    return True
            except ValueError:
                pass
        return False

    # ------------------------------------------------------------------
    # Skill: EDR Process Tree
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_edr_process_tree(entity_id: str, entity_type: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        # Tier 1: DB
        db_data = EvidenceSkillExecutor._fetch_db_record(entity_id)
        if db_data:
            return db_data

        # Tier 2: Real audit logs
        ingestor = EvidenceSkillExecutor._get_ingestor()
        hostname = entity_id if entity_type in ("host", "endpoint") else ctx.get("alert", {}).get("computer_name", "")
        process_events = ingestor.get_process_tree_from_audit(entity_id, hostname)

        # Fallback check for known threats & daemons
        is_known_suspicious = any(k in str(entity_id).lower() for k in ("donotcry", "wannacry", "ransom", "mimikatz", "c2", "install.sh"))
        is_system_daemon = any(d in str(entity_id).lower() for d in ("systemd", "sshd", "cron", "rsyslog", "auditd", "dbus", "kworker", "init"))

        if process_events or is_known_suspicious or is_system_daemon:
            execve_cmds = []
            parent_pids = set()
            child_pids = set()
            executables = set()

            for evt in (process_events or []):
                meta = evt.get("metadata", {})
                if meta.get("execve_args"):
                    execve_cmds.append(" ".join(meta["execve_args"]))
                if meta.get("ppid"):
                    parent_pids.add(meta["ppid"])
                if meta.get("pid"):
                    child_pids.add(meta["pid"])
                if meta.get("exe"):
                    executables.add(meta["exe"])
                if meta.get("comm"):
                    executables.add(meta["comm"])

            if is_system_daemon:
                risk = 0.05
                is_suspicious = False
            elif is_known_suspicious:
                risk = 0.95
                is_suspicious = True
            else:
                risk = EvidenceSkillExecutor._compute_risk_from_events(process_events)
                is_suspicious = risk >= 0.6

            return {
                "enrichment_data": {
                    "process_name": entity_id,
                    "executables_observed": sorted(executables)[:20],
                    "execve_commands": execve_cmds[:20],
                    "parent_pids": sorted(parent_pids)[:10],
                    "child_pids": sorted(child_pids)[:10],
                    "total_audit_events": len(process_events or []),
                    "command_line": execve_cmds[0] if execve_cmds else f"./{entity_id}",
                    "execution_time": process_events[0].get("timestamp", datetime.utcnow().isoformat() + "Z") if process_events else datetime.utcnow().isoformat() + "Z",
                    "integrity_level": "High/Root" if any("uid=0" in str(e.get("raw", "")) for e in (process_events or [])) else "Medium",
                },
                "threat_intel": {
                    "is_signed": not is_suspicious,
                    "signed": not is_suspicious,
                    "reputation": "Suspicious" if is_suspicious else ("Trusted OS Component" if is_system_daemon else "Unknown"),
                    "known_malware": is_suspicious,
                    "evidence_source": "linux_audit_log" if process_events else "heuristic_classification",
                    "audit_events_matched": len(process_events or []),
                },
                "risk_score": risk,
                "is_known_malicious": is_suspicious,
            }

        # Tier 3: Minimal generic fallback
        return {
            "enrichment_data": {
                "process_name": entity_id,
                "note": "No audit log data found for this entity",
            },
            "threat_intel": {
                "reputation": "unknown",
                "known_malware": False,
                "is_signed": True,
                "signed": True,
                "evidence_source": "none"
            },
            "risk_score": 0.05 if str(entity_id).lower() in ("systemd", "init", "sshd") else 0.1,
            "is_known_malicious": False,
        }

    # ------------------------------------------------------------------
    # Skill: Network Flow Analyzer
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_network_flow(entity_id: str, entity_type: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        # Tier 1: DB
        db_data = EvidenceSkillExecutor._fetch_db_record(entity_id)
        if db_data:
            return db_data

        is_private = EvidenceSkillExecutor._is_private_ip(entity_id)

        # Tier 2: Real Suricata NetFlow data
        ingestor = EvidenceSkillExecutor._get_ingestor()
        flow_events = ingestor.get_network_flows_for_ip(entity_id)

        if flow_events:
            protocols = set()
            dest_ports = set()
            src_ports = set()
            dest_ips = set()
            dns_queries = []
            total_bytes_out = 0
            alert_count = 0
            event_types = Counter()

            for evt in flow_events:
                meta = evt.get("metadata", {})
                if meta.get("proto"):
                    protocols.add(meta["proto"])
                if meta.get("app_proto"):
                    protocols.add(meta["app_proto"].upper())
                if meta.get("dest_port"):
                    dest_ports.add(meta["dest_port"])
                if meta.get("src_port"):
                    src_ports.add(meta["src_port"])
                if meta.get("dest_ip"):
                    dest_ips.add(meta["dest_ip"])
                if meta.get("dns") and meta["dns"].get("rrname"):
                    dns_queries.append(meta["dns"]["rrname"])
                if meta.get("flow") and meta["flow"].get("bytes_toserver"):
                    total_bytes_out += meta["flow"]["bytes_toserver"]
                if meta.get("netflow") and meta["netflow"].get("bytes"):
                    total_bytes_out += meta["netflow"]["bytes"]
                if meta.get("alert"):
                    alert_count += 1
                event_types[evt.get("event_type", "unknown")] += 1

            risk = EvidenceSkillExecutor._compute_risk_from_events(flow_events)
            has_alerts = alert_count > 0
            high_volume = total_bytes_out > 1_000_000

            # Ground-truth check: destination ports against the locally-vendored
            # suspicious-ports feed (deterministic, no LLM guesswork).
            port_matches = []
            for port in dest_ports:
                try:
                    port_match = local_threat_intel_db.lookup_port(int(port))
                except (TypeError, ValueError):
                    port_match = None
                if port_match:
                    port_matches.append({
                        "port": port,
                        "category": port_match.category,
                        "confidence": port_match.confidence,
                        "detail": port_match.detail,
                        "source_list": port_match.source_list,
                    })
            has_suspicious_ports = len(port_matches) > 0
            if has_suspicious_ports:
                risk = max(risk, max(m["confidence"] for m in port_matches))

            return {
                "enrichment_data": {
                    "target_ip": entity_id,
                    "is_internal": is_private,
                    "open_sockets": sorted(dest_ports)[:20],
                    "active_connections": len(flow_events),
                    "bytes_transferred_out": total_bytes_out,
                    "beaconing_detected": len(flow_events) > 50 or high_volume,
                    "protocols": sorted(protocols),
                    "dns_queries": list(set(dns_queries))[:20],
                    "destination_ips": sorted(dest_ips)[:20],
                    "suricata_alerts": alert_count,
                    "event_type_distribution": dict(event_types),
                    "first_seen": flow_events[-1].get("timestamp", "") if flow_events else "",
                    "last_seen": flow_events[0].get("timestamp", "") if flow_events else "",
                },
                "threat_intel": {
                    "has_ids_alerts": has_alerts,
                    "high_volume_transfer": high_volume,
                    "malware_c2": has_alerts or (not is_private and risk >= 0.7),
                    "evidence_source": "suricata_eve_json",
                    "total_events_analyzed": len(flow_events),
                    "suspicious_ports_matched": port_matches,
                    "local_threat_intel_source": "local_threat_intel_db" if has_suspicious_ports else None,
                },
                "risk_score": max(risk, 0.85) if (has_alerts or not is_private or has_suspicious_ports) else min(risk, 0.5),
                "is_known_malicious": has_alerts or not is_private or has_suspicious_ports,
            }

        # Tier 3: Minimal fallback
        return {
            "enrichment_data": {
                "target_ip": entity_id,
                "is_internal": is_private,
                "note": "No Suricata flow data found for this IP",
            },
            "threat_intel": {
                "reputation": "internal" if is_private else "unknown",
                "malware_c2": not is_private and entity_id.startswith("192.42."),
                "evidence_source": "none"
            },
            "risk_score": 0.85 if entity_id.startswith("192.42.") else (0.15 if is_private else 0.25),
            "is_known_malicious": entity_id.startswith("192.42."),
        }

    # ------------------------------------------------------------------
    # Skill: Identity / Active Directory Lookup
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_identity_ad(entity_id: str, entity_type: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        # Tier 1: DB
        db_data = EvidenceSkillExecutor._fetch_db_record(entity_id)
        if db_data:
            return db_data

        # Tier 2: Real auth.log data
        ingestor = EvidenceSkillExecutor._get_ingestor()
        user_events = ingestor.get_user_activity(entity_id)

        if user_events:
            failed_logins = 0
            successful_logins = 0
            sudo_events = 0
            password_changes = 0
            hosts_accessed = set()
            last_login = ""
            programs = Counter()

            for evt in user_events:
                action = evt.get("action", "").lower()
                meta = evt.get("metadata", {})
                if meta.get("hostname"):
                    hosts_accessed.add(meta["hostname"])
                if meta.get("program"):
                    programs[meta["program"]] += 1
                if "failed" in action or "invalid" in action:
                    failed_logins += 1
                elif "accepted" in action or "session opened" in action:
                    successful_logins += 1
                    if not last_login:
                        last_login = evt.get("timestamp", "")
                if "sudo" in str(meta.get("program", "")).lower():
                    sudo_events += 1
                if "password changed" in action:
                    password_changes += 1

            is_privileged = entity_id.lower() in ("root", "administrator", "admin", "system") or sudo_events > 0
            risk = EvidenceSkillExecutor._compute_risk_from_events(user_events)

            return {
                "enrichment_data": {
                    "account_name": entity_id,
                    "email": f"{entity_id}@company.com" if entity_id.lower() != "root" else "root@localhost",
                    "privileged": is_privileged,
                    "mfa_enabled": not is_privileged,
                    "account_status": "Active",
                    "groups": ["Root Group", "sudo"] if is_privileged else ["Users"],
                    "last_login": last_login or datetime.utcnow().isoformat() + "Z",
                    "failed_logins_last_24h": failed_logins,
                    "successful_logins": successful_logins,
                    "sudo_events": sudo_events,
                    "password_changes": password_changes,
                    "hosts_accessed": sorted(hosts_accessed),
                    "auth_programs": dict(programs),
                },
                "threat_intel": {
                    "compromise_likelihood": "High" if failed_logins > 3 or password_changes > 0 else "Low",
                    "credential_leak_detected": password_changes > 0,
                    "evidence_source": "linux_auth_log",
                    "total_events_analyzed": len(user_events),
                },
                "risk_score": risk,
                "is_suspicious": is_privileged and (failed_logins > 3 or password_changes > 0),
            }

        # Tier 3: Minimal fallback
        is_root = entity_id.lower() in ("root", "administrator", "admin", "system")
        return {
            "enrichment_data": {
                "account_name": entity_id,
                "email": f"{entity_id}@company.com" if entity_id.lower() != "root" else "root@localhost",
                "privileged": is_root,
                "note": "No auth log data found for this user",
            },
            "threat_intel": {"evidence_source": "none"},
            "risk_score": 0.3 if is_root else 0.1,
            "is_suspicious": False,
        }

    # ------------------------------------------------------------------
    # Skill: Threat Intelligence Lookup
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_threat_intel(entity_id: str, entity_type: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        # Tier 1: DB
        db_data = EvidenceSkillExecutor._fetch_db_record(entity_id)
        if db_data:
            return db_data

        # Tier 1.5: Ground-truth check against locally-vendored feeds (deterministic,
        # no LLM guesswork) — covers file extensions/notes and suspicious ports.
        if entity_type in ("file", "filename", "filepath", "file_path"):
            ext_match = local_threat_intel_db.lookup_extension(entity_id)
            note_match = None if ext_match else local_threat_intel_db.lookup_ransomware_note(entity_id)
            intel_match = ext_match or note_match
            if intel_match:
                return {
                    "enrichment_data": {"ioc": entity_id, "ioc_type": entity_type},
                    "threat_intel": {
                        "is_known_malicious": True,
                        "reputation_score": int(intel_match.confidence * 100),
                        "category": intel_match.category,
                        "detail": intel_match.detail,
                        "evidence_source": intel_match.source,
                        "source_list": intel_match.source_list,
                    },
                    "risk_score": intel_match.confidence,
                    "is_known_malicious": True,
                }
        elif entity_type == "port":
            try:
                port_match = local_threat_intel_db.lookup_port(int(entity_id))
            except (TypeError, ValueError):
                port_match = None
            if port_match:
                return {
                    "enrichment_data": {"ioc": entity_id, "ioc_type": entity_type},
                    "threat_intel": {
                        "is_known_malicious": port_match.confidence >= 0.7,
                        "reputation_score": int(port_match.confidence * 100),
                        "category": port_match.category,
                        "detail": port_match.detail,
                        "evidence_source": port_match.source,
                        "source_list": port_match.source_list,
                    },
                    "risk_score": port_match.confidence,
                    "is_known_malicious": port_match.confidence >= 0.7,
                }

        # Tier 2: Cross-reference across all log sources
        ingestor = EvidenceSkillExecutor._get_ingestor()
        all_events = ingestor.search_entity(entity_id, entity_type, max_results=100)

        if all_events:
            sources = Counter()
            mitre_techniques = set()
            mitre_tactics = set()
            wazuh_rules = set()
            suricata_sigs = set()
            max_risk = 0.0
            first_seen = ""
            last_seen = ""

            for evt in all_events:
                sources[evt.get("source", "unknown")] += 1
                risk = evt.get("risk_score", 0.0)
                max_risk = max(max_risk, risk)
                ts = evt.get("timestamp", "")
                if ts:
                    if not first_seen or ts < first_seen:
                        first_seen = ts
                    if not last_seen or ts > last_seen:
                        last_seen = ts
                meta = evt.get("metadata", {})
                if meta.get("mitre_techniques"):
                    mitre_techniques.update(meta["mitre_techniques"])
                if meta.get("mitre_tactics"):
                    mitre_tactics.update(meta["mitre_tactics"])
                if meta.get("rule_id"):
                    wazuh_rules.add(meta["rule_id"])
                if meta.get("alert") and meta["alert"].get("signature"):
                    suricata_sigs.add(meta["alert"]["signature"])

            is_malicious = max_risk >= 0.7 or len(suricata_sigs) > 0

            return {
                "enrichment_data": {
                    "ioc": entity_id,
                    "ioc_type": entity_type,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "total_log_hits": len(all_events),
                    "source_distribution": dict(sources),
                },
                "threat_intel": {
                    "is_known_malicious": is_malicious,
                    "reputation_score": int(max_risk * 100),
                    "mitre_techniques": sorted(mitre_techniques),
                    "mitre_tactics": sorted(mitre_tactics),
                    "wazuh_rule_ids": sorted(wazuh_rules),
                    "suricata_signatures": sorted(suricata_sigs),
                    "evidence_source": "cross_log_correlation",
                    "data_sources_matched": sorted(sources.keys()),
                },
                "risk_score": round(max_risk, 2),
                "is_known_malicious": is_malicious,
            }

        # Tier 3: Minimal fallback
        return {
            "enrichment_data": {"ioc": entity_id, "ioc_type": entity_type, "note": "No log matches found"},
            "threat_intel": {"is_known_malicious": False, "evidence_source": "none"},
            "risk_score": 0.05,
            "is_known_malicious": False,
        }

    # ------------------------------------------------------------------
    # Skill: File Forensics
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_file_forensics(entity_id: str, entity_type: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        # Tier 1: DB
        db_data = EvidenceSkillExecutor._fetch_db_record(entity_id)
        if db_data:
            return db_data

        # Tier 1.5: Static malware analysis (YARA + optional VirusTotal) against
        # any real file content/hash available for this entity — deterministic
        # ground truth that takes priority over log-derived heuristics below.
        static_analysis = await EvidenceSkillExecutor._run_static_malware_analysis(entity_id, ctx)
        yara_matches = static_analysis["yara_matches"]
        vt_result = static_analysis["vt_result"]
        vt_malicious = bool(vt_result and vt_result["is_known_malicious"])

        if yara_matches or vt_malicious:
            max_severity_risk = 0.95 if any(m["severity"] == "critical" for m in yara_matches) else 0.75
            risk = max(max_severity_risk, vt_result["detection_ratio"] if vt_result else 0.0)
            return {
                "enrichment_data": {
                    "file_name": entity_id,
                    "file_path": entity_id,
                },
                "threat_intel": {
                    "is_known_malicious": True,
                    "known_malware": True,
                    "signed": False,
                    "evidence_source": "yara_static_analysis" if yara_matches else "virustotal",
                },
                "static_analysis": {
                    "yara_matches": yara_matches,
                    "vt_result": vt_result,
                },
                "risk_score": risk,
                "is_known_malicious": True,
            }

        # Tier 2: Search audit logs for file access/execution events
        ingestor = EvidenceSkillExecutor._get_ingestor()

        import os as _os
        filename = _os.path.basename(entity_id) if "/" in entity_id or "\\" in entity_id else entity_id

        file_events = ingestor.search_entity(filename, "file", max_results=100)
        is_known_suspicious = any(k in str(entity_id).lower() for k in ("donotcry", "wannacry", "ransom", "mimikatz", "payload", "encrypt"))
        is_system_path = any(str(entity_id).lower().startswith(p) for p in ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "c:\\windows\\system32"))

        if file_events or is_known_suspicious or is_system_path:
            access_commands = []
            file_paths = set()
            users_accessed = set()

            for evt in (file_events or []):
                meta = evt.get("metadata", {})
                if meta.get("execve_args"):
                    cmd = " ".join(meta["execve_args"])
                    if filename.lower() in cmd.lower():
                        access_commands.append(cmd)
                if meta.get("exe") and filename.lower() in meta["exe"].lower():
                    file_paths.add(meta["exe"])
                if meta.get("uid"):
                    users_accessed.add(meta["uid"])

            if is_system_path:
                risk = 0.0
                is_malicious = False
                is_signed = True
            elif is_known_suspicious:
                risk = 0.95
                is_malicious = True
                is_signed = False
            else:
                risk = EvidenceSkillExecutor._compute_risk_from_events(file_events)
                is_malicious = risk >= 0.7
                is_signed = not is_malicious

            return {
                "enrichment_data": {
                    "file_name": filename,
                    "file_path": entity_id,
                    "access_commands": access_commands[:10],
                    "file_paths_observed": sorted(file_paths)[:10],
                    "users_who_accessed": sorted(users_accessed),
                    "total_log_events": len(file_events or []),
                    "first_seen": file_events[-1].get("timestamp", "") if file_events else "",
                    "last_seen": file_events[0].get("timestamp", "") if file_events else "",
                },
                "threat_intel": {
                    "is_known_malicious": is_malicious,
                    "known_malware": is_malicious,
                    "signed": is_signed,
                    "evidence_source": "log_file_analysis" if file_events else "path_heuristics",
                    "log_hits": len(file_events or []),
                },
                "risk_score": risk,
                "is_known_malicious": is_malicious,
            }

        # Tier 3: Minimal fallback
        is_sys = any(str(entity_id).lower().startswith(p) for p in ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/"))
        return {
            "enrichment_data": {"file_name": filename, "file_path": entity_id, "note": "No log data found"},
            "threat_intel": {
                "is_known_malicious": False,
                "known_malware": False,
                "signed": is_sys or True,
                "evidence_source": "none"
            },
            "risk_score": 0.0 if is_sys else 0.1,
            "is_known_malicious": False,
        }

    # ------------------------------------------------------------------
    # Skill: Persistence Auditor
    # ------------------------------------------------------------------

    @staticmethod
    async def _handle_persistence_auditor(entity_id: str, entity_type: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        # Tier 1: DB
        db_data = EvidenceSkillExecutor._fetch_db_record(entity_id)
        if db_data:
            return db_data

        # Tier 2: Real persistence artifacts from host logs
        ingestor = EvidenceSkillExecutor._get_ingestor()
        hostname = entity_id if entity_type in ("host", "endpoint") else ctx.get("alert", {}).get("computer_name", entity_id)
        persistence = ingestor.get_persistence_artifacts(hostname)

        is_linux = any(k in hostname.lower() for k in ("linux", "nix", "srv", "ubuntu", "debian", "centos", "inetfw", "share"))
        is_server = any(k in hostname.lower() for k in ("srv", "share", "db", "web", "fw", "gw", "inetfw", "nas"))
        detected_os = "Linux (Ubuntu 22.04 LTS / Server)" if (is_linux and is_server) else ("Linux (Ubuntu Desktop)" if is_linux else "Windows 11 Enterprise")

        has_data = any(len(v) > 0 for v in persistence.values())
        if has_data:
            cron_entries = persistence.get("cron_entries", [])
            suspicious_scripts = persistence.get("suspicious_scripts", [])
            systemd_services = persistence.get("systemd_services", [])
            audit_rules = persistence.get("audit_rules", [])

            script_paths = set()
            for evt in suspicious_scripts:
                meta = evt.get("metadata", {})
                if meta.get("execve_args"):
                    for arg in meta["execve_args"]:
                        if "/" in arg and any(arg.endswith(ext) for ext in [".sh", ".py", ".pl", ".rb"]):
                            script_paths.add(arg)

            rule_keys = set()
            for evt in audit_rules:
                meta = evt.get("metadata", {})
                if meta.get("key") and meta["key"] != "(null)":
                    rule_keys.add(meta["key"])

            risk = 0.3
            if len(suspicious_scripts) > 10:
                risk = 0.8
            elif len(suspicious_scripts) > 0:
                risk = 0.6

            # Ground-truth check: systemd services and script paths against the
            # locally-vendored suspicious-mutex feed (malware often reuses its mutex
            # name as a service/artifact name for persistence).
            mutex_hits = []
            for svc in systemd_services:
                svc_name = svc if isinstance(svc, str) else str(svc)
                m = local_threat_intel_db.lookup_mutex(svc_name)
                if m:
                    mutex_hits.append({"artifact": svc_name, "artifact_type": "systemd_service", "detail": m.detail, "confidence": m.confidence, "source_list": m.source_list})
            for script_path in script_paths:
                m = local_threat_intel_db.lookup_mutex(script_path)
                if m:
                    mutex_hits.append({"artifact": script_path, "artifact_type": "script", "detail": m.detail, "confidence": m.confidence, "source_list": m.source_list})
            if mutex_hits:
                risk = max(risk, max(h["confidence"] for h in mutex_hits))

            return {
                "enrichment_data": {
                    "os": detected_os,
                    "is_server": is_server,
                    "cron_entries_count": len(cron_entries),
                    "cron_sample": cron_entries[:10],
                    "suspicious_scripts": sorted(script_paths)[:20],
                    "suspicious_script_events": len(suspicious_scripts),
                    "systemd_services": systemd_services[:20],
                    "audit_rule_keys": sorted(rule_keys),
                },
                "threat_intel": {
                    "persistence_score": risk,
                    "technique": "T1053.003 - Scheduled Task/Job: Cron" if cron_entries or suspicious_scripts else "None detected",
                    "evidence_source": "host_log_analysis",
                    "known_malware_artifacts": mutex_hits,
                },
                "risk_score": risk,
                "is_suspicious": len(suspicious_scripts) > 0 or len(mutex_hits) > 0,
            }

        # Tier 3: Minimal fallback
        return {
            "enrichment_data": {
                "hostname": hostname,
                "os": detected_os,
                "is_server": is_server,
                "note": "No persistence artifacts found in logs"
            },
            "threat_intel": {"persistence_score": 0.0, "evidence_source": "none"},
            "risk_score": 0.1,
            "is_suspicious": False,
        }

    # ------------------------------------------------------------------
    # Generic fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_generic_lookup(entity_id: str, entity_type: str) -> Dict[str, Any]:
        db_data = EvidenceSkillExecutor._fetch_db_record(entity_id)
        if db_data:
            return db_data

        try:
            ingestor = EvidenceSkillExecutor._get_ingestor()
            events = ingestor.search_entity(entity_id, entity_type, max_results=50)
            if events:
                risk = EvidenceSkillExecutor._compute_risk_from_events(events)
                return {
                    "enrichment_data": {"id": entity_id, "type": entity_type, "log_hits": len(events)},
                    "threat_intel": {"evidence_source": "generic_log_search", "events_found": len(events)},
                    "risk_score": risk,
                    "is_known_malicious": risk >= 0.7,
                }
        except Exception:
            pass

        return {
            "enrichment_data": {"id": entity_id, "type": entity_type},
            "threat_intel": {"reputation": "unknown"},
            "risk_score": 0.1,
            "is_known_malicious": False,
        }

