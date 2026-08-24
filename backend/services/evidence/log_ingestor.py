"""Generic Log Ingestor — Parses real SIEM/EDR/System logs from ANY dataset directory.

Auto-discovers and classifies log files by content format, not by folder structure
or naming convention. Works with any directory layout.

Supported log formats (auto-detected):
- Wazuh SIEM alerts (JSONL with "rule" + "agent" fields)
- Suricata IDS eve.json (JSONL with "event_type" field)
- Linux audit.log (lines starting with "type=" and containing "msg=audit(")
- Linux auth.log / syslog (ISO-timestamp syslog lines)
- Generic syslog (traditional syslog format)

Usage:
    ingestor = LogIngestor(dataset_path="/any/path/to/logs")
    events = ingestor.search_entity("linuxshare", entity_type="host")
    events = ingestor.search_entity("192.42.1.174", entity_type="ip")
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict
from enum import Enum

logger = logging.getLogger("log-ingestor")

# Default dataset path — override with DATASET_PATH env var
DEFAULT_DATASET_PATH = os.getenv(
    "DATASET_PATH",
    r"D:\projects\sxsecurityinvestigator\data\logs\CAM-LDS-team-messy"
)


class LogFormat(Enum):
    """Auto-detected log file format."""
    WAZUH_JSON = "wazuh_json"
    SURICATA_JSON = "suricata_json"
    AUDIT_LOG = "audit_log"
    AUTH_SYSLOG = "auth_syslog"
    GENERIC_SYSLOG = "generic_syslog"
    UNKNOWN = "unknown"


class LogIngestor:
    """Generic log file parser that reads real forensic logs from any dataset directory.

    On first use, recursively scans the dataset directory, reads the first
    few lines of each text file, and classifies it by content format. This means
    the same code works regardless of folder structure or naming convention.
    """

    # File extensions we never try to read as text
    BINARY_EXTENSIONS = {
        ".gz", ".bz2", ".xz", ".zst", ".zip", ".tar", ".pcap", ".pcapng",
        ".db", ".sqlite", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".exe", ".dll", ".so", ".bin", ".dat",
    }

    # Maximum file size to scan (skip huge files)
    MAX_CLASSIFY_BYTES = 500 * 1024 * 1024  # 500 MB

    def __init__(self, dataset_path: Optional[str] = None):
        self.dataset_path = dataset_path or DEFAULT_DATASET_PATH
        self._catalog: Dict[LogFormat, List[str]] = defaultdict(list)
        self._host_map: Dict[str, List[str]] = defaultdict(list)  # hostname -> file paths
        self._file_cache: Dict[str, str] = {}  # In-memory text cache
        self._classified = False

    def _ensure_classified(self):
        """Lazy classification — only scan files on first use."""
        if not self._classified:
            self._classify_all_files()
            self._classified = True

    def _get_file_content(self, filepath: str) -> str:
        """Get file content with in-memory caching for sub-millisecond searches."""
        if filepath not in self._file_cache:
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    self._file_cache[filepath] = f.read()
            except Exception as e:
                logger.error(f"Error reading {filepath}: {e}")
                self._file_cache[filepath] = ""
        return self._file_cache[filepath]

    # ------------------------------------------------------------------
    # Auto-discovery & classification
    # ------------------------------------------------------------------

    def _classify_all_files(self):
        """Recursively scan dataset directory and classify every file by content."""
        if not os.path.isdir(self.dataset_path):
            logger.warning(f"Dataset path not found: {self.dataset_path}")
            return

        file_count = 0
        for root, dirs, files in os.walk(self.dataset_path):
            for fname in files:
                filepath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                # Skip binary files
                if ext in self.BINARY_EXTENSIONS:
                    continue

                # Skip files with no extension that look binary (btmp, wtmp, lastlog, pacct)
                if not ext and any(bname in fname.lower() for bname in
                                   ["btmp", "wtmp", "lastlog", "faillog", "pacct"]):
                    continue

                # Skip oversized or empty files
                try:
                    fsize = os.path.getsize(filepath)
                    if fsize > self.MAX_CLASSIFY_BYTES or fsize == 0:
                        continue
                except OSError:
                    continue

                fmt = self._classify_file(filepath)
                if fmt != LogFormat.UNKNOWN:
                    self._catalog[fmt].append(filepath)
                    file_count += 1

                    # Try to extract hostname from path for host-based lookups
                    hostname = self._extract_hostname_from_path(filepath, fname)
                    if hostname:
                        self._host_map[hostname].append(filepath)

        logger.info(
            f"Classified {file_count} log files from {self.dataset_path}: "
            + ", ".join(f"{fmt.value}={len(paths)}" for fmt, paths in self._catalog.items())
        )

    def _classify_file(self, filepath: str) -> LogFormat:
        """Read first few lines of a file and determine its format."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                sample_lines = []
                for _ in range(20):
                    line = f.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    if stripped:
                        sample_lines.append(stripped)
                    if len(sample_lines) >= 5:
                        break

            if not sample_lines:
                return LogFormat.UNKNOWN

            # Majority vote from sample lines
            format_votes: Dict[LogFormat, int] = defaultdict(int)
            for line in sample_lines:
                fmt = self._classify_line(line)
                format_votes[fmt] += 1

            if not format_votes:
                return LogFormat.UNKNOWN

            best_fmt = max(format_votes, key=format_votes.get)
            # Need at least 2 votes or only 1-2 sample lines
            return best_fmt if format_votes[best_fmt] >= 2 or len(sample_lines) <= 2 else best_fmt

        except Exception:
            return LogFormat.UNKNOWN

    @staticmethod
    def _classify_line(line: str) -> LogFormat:
        """Classify a single line by its content format."""
        # JSON line — check structure
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                # Wazuh: has "rule" dict and "agent" dict
                if "rule" in obj and "agent" in obj:
                    return LogFormat.WAZUH_JSON
                # Suricata: has "event_type" field
                if "event_type" in obj:
                    return LogFormat.SURICATA_JSON
            except json.JSONDecodeError:
                pass
            return LogFormat.UNKNOWN

        # Linux audit.log: starts with "type=" and contains "msg=audit("
        if line.startswith("type=") and "msg=audit(" in line:
            return LogFormat.AUDIT_LOG

        # ISO-timestamp syslog: 2025-12-12T17:19:53.069010+00:00 hostname ...
        if re.match(r"\d{4}-\d{2}-\d{2}T[\d:.+]+\s+\S+\s+\S+", line):
            if any(prog in line.lower() for prog in
                   ["sshd", "sudo", "pam_", "cron", "su:", "login", "chpasswd", "systemd-logind"]):
                return LogFormat.AUTH_SYSLOG
            return LogFormat.GENERIC_SYSLOG

        # Traditional syslog: "Dec 12 17:19:53 hostname ..."
        if re.match(r"[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+", line):
            if any(prog in line.lower() for prog in
                   ["sshd", "sudo", "pam_", "cron", "su:", "login"]):
                return LogFormat.AUTH_SYSLOG
            return LogFormat.GENERIC_SYSLOG

        return LogFormat.UNKNOWN

    @staticmethod
    def _extract_hostname_from_path(filepath: str, fname: str) -> Optional[str]:
        """Try to extract a hostname from the file path or name.

        Handles multiple naming patterns:
        - "hostname__log_type.log" (CAM-LDS style)
        - "hostname/audit.log" (directory-per-host)
        - "hostname-audit.log" (dash-separated)
        """
        # Pattern 1: hostname__log (double underscore separator)
        if "__" in fname:
            return fname.split("__")[0].lower()

        # Pattern 2: parent directory is the hostname
        parent = os.path.basename(os.path.dirname(filepath)).lower()
        generic_dirs = {"logs", "log", "security", "network", "system", "application",
                        "data", "var", "etc", "tmp", "audit", "syslog", "hosts"}
        if parent and parent not in generic_dirs and not parent.startswith("."):
            return parent

        # Pattern 3: hostname-type.log (dash separator)
        if "-" in fname:
            parts = fname.split("-")
            candidate = parts[0].lower()
            if len(candidate) > 2 and candidate.isalpha():
                return candidate

        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def search_entity(
        self,
        entity_id: str,
        entity_type: str = "unknown",
        max_results: int = 200,
    ) -> List[Dict[str, Any]]:
        """Search all log sources for events related to an entity.

        Works with any dataset — discovers files by content, not by name.

        Args:
            entity_id: The entity value (IP, hostname, username, filename, hash).
            entity_type: One of 'host', 'ip', 'user', 'file', 'process', 'domain'.
            max_results: Max events to return.

        Returns:
            List of normalized event dicts.
        """
        self._ensure_classified()

        if not self._catalog:
            logger.warning(f"No classified log files in {self.dataset_path}")
            return []

        results: List[Dict[str, Any]] = []
        entity_lower = entity_id.lower()

        # Search each format
        for fmt in (LogFormat.WAZUH_JSON, LogFormat.SURICATA_JSON, LogFormat.AUDIT_LOG,
                    LogFormat.AUTH_SYSLOG, LogFormat.GENERIC_SYSLOG):
            for filepath in self._catalog.get(fmt, []):
                results.extend(self._search_file_for_entity(
                    filepath, entity_lower, fmt, max_results - len(results)
                ))
                if len(results) >= max_results:
                    break
            if len(results) >= max_results:
                break

        results.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return results[:max_results]

    def _search_file_for_entity(self, filepath: str, entity_lower: str,
                                 fmt: LogFormat, remaining: int) -> List[Dict[str, Any]]:
        """Search a single file for lines containing the entity."""
        results = []
        if remaining <= 0:
            return results
        content = self._get_file_content(filepath)
        if not content or entity_lower not in content.lower():
            return results
        for line in content.splitlines():
            if entity_lower in line.lower():
                parsed = self._parse_line(line.strip(), fmt)
                if parsed:
                    results.append(parsed)
            if len(results) >= remaining:
                break
        return results

    def _parse_line(self, line: str, fmt: LogFormat) -> Optional[Dict[str, Any]]:
        """Parse a line according to its detected format."""
        if fmt == LogFormat.WAZUH_JSON:
            try:
                return self._normalize_wazuh_event(json.loads(line))
            except json.JSONDecodeError:
                return None
        elif fmt == LogFormat.SURICATA_JSON:
            try:
                return self._normalize_suricata_event(json.loads(line))
            except json.JSONDecodeError:
                return None
        elif fmt == LogFormat.AUDIT_LOG:
            return self._parse_audit_line(line)
        elif fmt in (LogFormat.AUTH_SYSLOG, LogFormat.GENERIC_SYSLOG):
            return self._parse_auth_line(line)
        return None

    def get_host_logs(self, hostname: str) -> Dict[str, List[Dict[str, Any]]]:
        """Get all log types for a specific host."""
        self._ensure_classified()
        result = {"audit": [], "auth": [], "suricata": [], "wazuh": [], "system": []}
        hostname_lower = hostname.lower()

        # Host-mapped files
        for filepath in self._host_map.get(hostname_lower, []):
            fmt = self._get_format_of_file(filepath)
            if fmt == LogFormat.AUDIT_LOG:
                result["audit"].extend(self._parse_file(filepath, fmt, limit=500))
            elif fmt == LogFormat.AUTH_SYSLOG:
                result["auth"].extend(self._parse_file(filepath, fmt, limit=200))
            elif fmt == LogFormat.GENERIC_SYSLOG:
                result["system"].extend(self._parse_file(filepath, fmt, limit=200))

        # Suricata and Wazuh are typically global
        for filepath in self._catalog.get(LogFormat.SURICATA_JSON, []):
            result["suricata"].extend(self._parse_file(filepath, LogFormat.SURICATA_JSON, limit=500))
        for filepath in self._catalog.get(LogFormat.WAZUH_JSON, []):
            result["wazuh"].extend(self._parse_file(filepath, LogFormat.WAZUH_JSON, limit=300))

        return result

    def get_network_flows_for_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """Get all Suricata NetFlow/DNS/TLS events for an IP."""
        self._ensure_classified()
        results = []
        ip_lower = ip_address.lower()
        for filepath in self._catalog.get(LogFormat.SURICATA_JSON, []):
            results.extend(self._search_file_for_entity(
                filepath, ip_lower, LogFormat.SURICATA_JSON, 2000 - len(results)
            ))
        return results

    def get_process_tree_from_audit(self, entity_id: str, hostname: str = "") -> List[Dict[str, Any]]:
        """Extract EXECVE and process creation events from audit.log."""
        self._ensure_classified()
        results = []
        entity_lower = entity_id.lower()

        if hostname:
            search_files = [fp for fp in self._host_map.get(hostname.lower(), [])
                           if self._get_format_of_file(fp) == LogFormat.AUDIT_LOG]
        else:
            search_files = self._catalog.get(LogFormat.AUDIT_LOG, [])

        for filepath in search_files:
            content = self._get_file_content(filepath)
            if not content or entity_lower not in content.lower():
                continue
            for line in content.splitlines():
                if entity_lower in line.lower():
                    parsed = self._parse_audit_line(line)
                    if parsed and parsed.get("event_type") in ("EXECVE", "SYSCALL", "CWD", "PATH"):
                        results.append(parsed)

        return results[:500]

    def get_persistence_artifacts(self, hostname: str) -> Dict[str, Any]:
        """Extract cron jobs, systemd services, and persistence indicators."""
        self._ensure_classified()
        hostname_lower = hostname.lower()
        persistence = {
            "cron_entries": [],
            "systemd_services": [],
            "suspicious_scripts": [],
            "audit_rules": [],
        }

        host_files = self._host_map.get(hostname_lower, [])

        for filepath in host_files:
            fmt = self._get_format_of_file(filepath)
            content = self._get_file_content(filepath)
            if not content:
                continue

            if fmt == LogFormat.AUDIT_LOG:
                for line in content.splitlines():
                    ll = line.lower()
                    if ("healthcheck" in ll or "cron" in ll) and "execve" in ll:
                        parsed = self._parse_audit_line(line)
                        if parsed:
                            persistence["suspicious_scripts"].append(parsed)
                    elif "config_change" in ll:
                        parsed = self._parse_audit_line(line)
                        if parsed:
                            persistence["audit_rules"].append(parsed)

            elif fmt in (LogFormat.AUTH_SYSLOG, LogFormat.GENERIC_SYSLOG):
                for line in content.splitlines():
                    ll = line.lower()
                    if "cron" in ll:
                        persistence["cron_entries"].append(line.strip())
                    elif "systemd" in ll or "healthcheck" in ll or ".service" in ll:
                        persistence["systemd_services"].append(line.strip())

        return persistence

    def get_user_activity(self, username: str) -> List[Dict[str, Any]]:
        """Get all auth events for a user across all hosts."""
        self._ensure_classified()
        results = []
        user_lower = username.lower()
        for filepath in self._catalog.get(LogFormat.AUTH_SYSLOG, []):
            results.extend(self._search_file_for_entity(
                filepath, user_lower, LogFormat.AUTH_SYSLOG, 200 - len(results)
            ))
            if len(results) >= 200:
                break
        return results

    def get_catalog_summary(self) -> Dict[str, Any]:
        """Return a summary of discovered log files and their types."""
        self._ensure_classified()
        return {
            "dataset_path": self.dataset_path,
            "formats": {fmt.value: len(paths) for fmt, paths in self._catalog.items()},
            "hosts_detected": sorted(self._host_map.keys()),
            "total_files": sum(len(p) for p in self._catalog.values()),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_format_of_file(self, filepath: str) -> LogFormat:
        """Look up the format of an already-classified file."""
        for fmt, paths in self._catalog.items():
            if filepath in paths:
                return fmt
        return LogFormat.UNKNOWN

    def _parse_file(self, filepath: str, fmt: LogFormat, limit: int = 500) -> List[Dict[str, Any]]:
        """Parse an entire file and return normalized events."""
        results = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parsed = self._parse_line(line.strip(), fmt)
                    if parsed:
                        results.append(parsed)
                    if len(results) >= limit:
                        break
        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")
        return results

    # ------------------------------------------------------------------
    # Format-specific parsers (generic — not tied to any dataset)
    # ------------------------------------------------------------------

    def _normalize_wazuh_event(self, obj: Dict) -> Dict[str, Any]:
        rule = obj.get("rule", {})
        agent = obj.get("agent", {})
        data = obj.get("data", {})
        return {
            "timestamp": obj.get("timestamp", ""),
            "source": "wazuh",
            "event_type": "siem_alert",
            "entity": agent.get("name", "unknown"),
            "action": rule.get("description", ""),
            "risk_score": min(rule.get("level", 0) / 15.0, 1.0),
            "metadata": {
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "groups": rule.get("groups", []),
                "mitre_techniques": rule.get("mitre_techniques", []),
                "mitre_tactics": rule.get("mitre_tactics", []),
                "agent_id": agent.get("id"),
                "agent_name": agent.get("name"),
                "full_log": obj.get("full_log", ""),
                "data": data,
            },
            "raw": obj,
        }

    def _normalize_suricata_event(self, obj: Dict) -> Dict[str, Any]:
        event_type = obj.get("event_type", "unknown")
        alert_data = obj.get("alert", {})
        return {
            "timestamp": obj.get("timestamp", ""),
            "source": "suricata",
            "event_type": f"ids_{event_type}",
            "entity": obj.get("src_ip", "unknown"),
            "action": alert_data.get("signature", "") if event_type == "alert" else event_type,
            "risk_score": self._suricata_severity_to_risk(alert_data.get("severity", 0) if alert_data else 0),
            "metadata": {
                "src_ip": obj.get("src_ip"),
                "src_port": obj.get("src_port"),
                "dest_ip": obj.get("dest_ip"),
                "dest_port": obj.get("dest_port"),
                "proto": obj.get("proto"),
                "app_proto": obj.get("app_proto"),
                "flow_id": obj.get("flow_id"),
                "community_id": obj.get("community_id"),
                "alert": alert_data if alert_data else None,
                "dns": obj.get("dns"),
                "tls": obj.get("tls"),
                "http": obj.get("http"),
                "flow": obj.get("flow"),
                "netflow": obj.get("netflow"),
            },
            "raw": obj,
        }

    def _parse_audit_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single Linux audit.log line into a normalized event."""
        line = line.strip()
        if not line:
            return None

        type_match = re.match(r"type=(\w+)", line)
        event_type = type_match.group(1) if type_match else "UNKNOWN"

        ts_match = re.search(r"msg=audit\((\d+\.\d+):\d+\)", line)
        timestamp = ""
        if ts_match:
            try:
                epoch = float(ts_match.group(1))
                timestamp = datetime.utcfromtimestamp(epoch).isoformat() + "Z"
            except (ValueError, OSError):
                pass

        kv_pairs = {}
        for match in re.finditer(r'(\w+)="([^"]*)"', line):
            kv_pairs[match.group(1)] = match.group(2)
        for match in re.finditer(r'(\w+)=([^\s"]+)', line):
            key = match.group(1)
            if key not in kv_pairs:
                kv_pairs[key] = match.group(2)

        execve_args = []
        if event_type == "EXECVE":
            for match in re.finditer(r'a\d+="([^"]*)"', line):
                execve_args.append(match.group(1))

        action = ""
        if event_type == "EXECVE" and execve_args:
            action = " ".join(execve_args)
        elif event_type == "SYSCALL":
            action = f"syscall={kv_pairs.get('syscall', '?')} comm={kv_pairs.get('comm', '?')} exe={kv_pairs.get('exe', '?')}"
        elif event_type in ("USER_ACCT", "CRED_ACQ", "CRED_DISP", "USER_START", "USER_END"):
            action = f"{event_type} acct={kv_pairs.get('acct', '?')} exe={kv_pairs.get('exe', '?')}"
        elif event_type == "CONFIG_CHANGE":
            action = f"audit_rule key={kv_pairs.get('key', '?')}"
        else:
            action = event_type

        # Generic risk heuristic — no hardcoded filenames
        risk = 0.1
        action_lower = action.lower()
        if any(k in action_lower for k in ["curl", "wget", "nc ", "bash -c", "python -c", "perl -e"]):
            risk = 0.9
        elif any(k in action_lower for k in ["cron", "chmod", "chown", "useradd", "usermod", "passwd"]):
            risk = 0.6
        elif event_type in ("CONFIG_CHANGE",):
            risk = 0.5

        return {
            "timestamp": timestamp,
            "source": "audit",
            "event_type": event_type,
            "entity": kv_pairs.get("comm", kv_pairs.get("exe", kv_pairs.get("acct", "unknown"))),
            "action": action,
            "risk_score": risk,
            "metadata": {
                "uid": kv_pairs.get("uid"),
                "auid": kv_pairs.get("auid"),
                "pid": kv_pairs.get("pid"),
                "ppid": kv_pairs.get("ppid"),
                "comm": kv_pairs.get("comm"),
                "exe": kv_pairs.get("exe"),
                "key": kv_pairs.get("key"),
                "execve_args": execve_args if execve_args else None,
                "success": kv_pairs.get("success"),
            },
            "raw": line,
        }

    def _parse_auth_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a syslog-formatted auth.log line."""
        line = line.strip()
        if not line:
            return None

        # ISO syslog
        match = re.match(
            r"(\d{4}-\d{2}-\d{2}T[\d:.+]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)",
            line,
        )
        if not match:
            # Traditional syslog
            match = re.match(
                r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)",
                line,
            )
        if not match:
            return None

        timestamp, hostname, program, pid, message = match.groups()

        risk = 0.1
        msg_lower = message.lower()
        if "failed" in msg_lower or "invalid" in msg_lower:
            risk = 0.7
        elif "accepted" in msg_lower or "session opened" in msg_lower:
            risk = 0.3
        elif "password changed" in msg_lower:
            risk = 0.6
        elif "sudo" in program.lower():
            risk = 0.5

        return {
            "timestamp": timestamp,
            "source": "auth",
            "event_type": f"auth_{program.lower()}",
            "entity": hostname,
            "action": message,
            "risk_score": risk,
            "metadata": {
                "hostname": hostname,
                "program": program,
                "pid": pid,
                "message": message,
            },
            "raw": line,
        }

    @staticmethod
    def _suricata_severity_to_risk(severity: int) -> float:
        """Convert Suricata severity (1=highest, 4=lowest) to risk score."""
        mapping = {1: 0.95, 2: 0.7, 3: 0.4, 4: 0.1}
        return mapping.get(severity, 0.2)


# Singleton
_ingestor: Optional[LogIngestor] = None


def get_log_ingestor(dataset_path: Optional[str] = None) -> LogIngestor:
    """Get or create the log ingestor singleton."""
    global _ingestor
    if _ingestor is None or (dataset_path and _ingestor.dataset_path != dataset_path):
        _ingestor = LogIngestor(dataset_path)
    return _ingestor
