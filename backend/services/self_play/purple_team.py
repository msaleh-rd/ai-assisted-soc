"""Self-Play Purple Team — Wave 3 / Phase L.

Red-teams the Detection-as-Code ruleset (Phase H) by replaying canned,
synthetic attack-technique event sequences through the real
`DetectionEngine.match_event()` call, records whether each technique in the
campaign was caught by an enabled rule (and how long the match took), and
computes a coverage percentage. Any technique that wasn't caught gets a
draft (`enabled: false`) YAML detection-rule proposal auto-filed under
`backend/detections/drafts/` for human review -- never auto-enabled.

Scoping note (documented, not silently skipped): the plan describes
injecting logs "through the real pipeline (using the same ingestion path as
production alerts, not a shortcut)". The production ingestion path today
(`alert_intake.py`) does not call `DetectionEngine.match_event()` at all yet
-- a gap already documented when Phase H was built (the engine stays a
standalone interpreter, not yet migrated into live ingestion, to limit
regression risk). Since this phase explicitly depends on and scores coverage
against Phase H's ruleset specifically, "the real pipeline" here is the
actual `DetectionEngine.match_event()` call -- the only real capability in
this codebase that knows about MITRE-technique-tagged rules -- rather than
the LLM-based 5-agent investigation pipeline, which has no per-technique
rule-detection concept to score coverage against.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from backend.services.detection_engine import DetectionEngine, DEFAULT_DETECTIONS_DIR

logger = logging.getLogger("purple_team")

DRAFT_RULES_DIR = DEFAULT_DETECTIONS_DIR / "drafts"


@dataclass
class CampaignStep:
    """One technique-step within a canned attack campaign."""
    technique_id: str
    technique_name: str
    synthetic_event: Dict[str, Any]


CANNED_CAMPAIGNS: Dict[str, List[CampaignStep]] = {
    "ransomware_chain": [
        CampaignStep(
            technique_id="T1566.001",
            technique_name="Phishing: Spearphishing Attachment",
            synthetic_event={
                "event_type": "email_attachment_opened",
                "file_name": "invoice_Q3.docm",
                "sender": "external-billing@totally-legit-vendor.example",
                "macro_enabled": True,
            },
        ),
        CampaignStep(
            technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            synthetic_event={
                "event_type": "process_creation",
                "process_name": "powershell.exe",
                "command_line": "powershell -enc SQBFAFgA",
                "parent_process": "winword.exe",
            },
        ),
        CampaignStep(
            technique_id="T1547.001",
            technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
            synthetic_event={
                "event_type": "registry_modification",
                "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "value_name": "SecurityHealthService",
                "value_data": r"C:\Users\Public\update.exe",
            },
        ),
        CampaignStep(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            synthetic_event={
                "event_type": "file_write",
                "file_extension": ".locked",
                "file_count_modified": 5000,
                "ransom_note_dropped": True,
            },
        ),
    ],
    "credential_theft_chain": [
        CampaignStep(
            technique_id="T1078",
            technique_name="Valid Accounts",
            synthetic_event={
                "event_type": "login_success",
                "username": "svc_backup",
                "source_ip": "203.0.113.44",
                "geo_anomaly": True,
            },
        ),
        CampaignStep(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            synthetic_event={
                "event_type": "process_creation",
                "process_name": "procdump.exe",
                "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
            },
        ),
        CampaignStep(
            technique_id="T1021.001",
            technique_name="Remote Services: Remote Desktop Protocol",
            synthetic_event={
                "event_type": "network_logon",
                "logon_type": "RemoteInteractive",
                "dest_host": "DC-01",
                "source_host": "WKS-042",
            },
        ),
        CampaignStep(
            technique_id="T1048",
            technique_name="Exfiltration Over Alternative Protocol",
            synthetic_event={
                "event_type": "network_connection",
                "dest_port": 8443,
                "bytes_out": 500_000_000,
                "protocol": "https",
                "dest_ip": "198.51.100.7",
            },
        ),
    ],
}


@dataclass
class TechniqueDetectionResult:
    """Whether a single campaign technique-step was caught by the ruleset."""
    technique_id: str
    technique_name: str
    detected: bool
    matched_rule_ids: List[str] = field(default_factory=list)
    detection_latency_ms: float = 0.0


@dataclass
class CampaignResult:
    """Full result of replaying a canned campaign against the DetectionEngine."""
    campaign_name: str
    technique_results: List[TechniqueDetectionResult]
    coverage_percentage: float
    draft_rules_filed: List[str] = field(default_factory=list)


class SelfPlayCampaign:
    """Replays canned attack campaigns against a real DetectionEngine and
    files draft rule proposals for any uncovered technique."""

    def __init__(self, engine: Optional[DetectionEngine] = None, draft_rules_dir: Path = DRAFT_RULES_DIR):
        self.engine = engine if engine is not None else DetectionEngine()
        self.draft_rules_dir = draft_rules_dir

    def run_campaign(self, campaign_name: str) -> CampaignResult:
        """Injects every step of the named canned campaign through the real
        DetectionEngine, in order, and returns a full coverage report."""
        steps = CANNED_CAMPAIGNS.get(campaign_name)
        if not steps:
            raise ValueError(f"Unknown campaign '{campaign_name}' (known: {list(CANNED_CAMPAIGNS.keys())})")

        technique_results: List[TechniqueDetectionResult] = []
        draft_rules_filed: List[str] = []
        for step in steps:
            start = time.time()
            matches = self.engine.match_event(step.synthetic_event)
            latency_ms = (time.time() - start) * 1000
            detected = len(matches) > 0
            technique_results.append(TechniqueDetectionResult(
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                detected=detected,
                matched_rule_ids=[m.rule_id for m in matches],
                detection_latency_ms=latency_ms,
            ))
            if not detected:
                filed_path = self._file_draft_rule(step)
                if filed_path:
                    draft_rules_filed.append(filed_path)

        covered = sum(1 for r in technique_results if r.detected)
        coverage_percentage = (covered / len(technique_results)) * 100.0 if technique_results else 0.0

        return CampaignResult(
            campaign_name=campaign_name,
            technique_results=technique_results,
            coverage_percentage=coverage_percentage,
            draft_rules_filed=draft_rules_filed,
        )

    def _file_draft_rule(self, step: CampaignStep) -> Optional[str]:
        """Auto-files a draft (enabled: false) YAML detection rule proposal for
        an uncovered technique, for human review -- never auto-enables itself,
        and is harmless even if immediately reloaded by a live DetectionEngine
        (disabled rules never match, per DetectionRule.evaluate())."""
        try:
            self.draft_rules_dir.mkdir(parents=True, exist_ok=True)
            rule_id = f"draft-{step.technique_id.lower().replace('.', '-')}-{uuid.uuid4().hex[:6]}"
            conditions = []
            for field_name, value in step.synthetic_event.items():
                op = "gte" if isinstance(value, (int, float)) and not isinstance(value, bool) else "equals"
                conditions.append({"field": field_name, "op": op, "value": value})

            draft = {
                "id": rule_id,
                "name": f"[DRAFT] Coverage gap: {step.technique_name} ({step.technique_id})",
                "severity": "medium",
                "category": "self-play-draft",
                "tags": [f"mitre.attack.{step.technique_id}", "self-play-draft", "needs-review"],
                "log_source": step.synthetic_event.get("event_type", "unknown"),
                "enabled": False,
                "detection": {
                    "condition": "all",
                    "rules": conditions,
                },
                "false_positives": (
                    "Auto-generated draft from a Self-Play Purple Team coverage gap "
                    "(Wave 3, Phase L); needs human review and tuning before enabling."
                ),
            }
            out_path = self.draft_rules_dir / f"{rule_id}.yaml"
            with open(out_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(draft, f, sort_keys=False)
            logger.info(f"Filed draft detection rule '{rule_id}' for uncovered technique {step.technique_id} at {out_path}")
            return str(out_path)
        except Exception as e:
            logger.warning(f"Failed to file draft rule for {step.technique_id}: {e}")
            return None
