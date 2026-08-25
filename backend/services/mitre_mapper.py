import re
import logging
from dataclasses import dataclass
from typing import Optional, Dict

logger = logging.getLogger("mitre_mapper")

@dataclass
class MitreTechnique:
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str] = None
    confidence: float = 0.95

    def to_dict(self) -> Dict:
        return {
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "subtechnique_id": self.subtechnique_id,
            "confidence": self.confidence,
        }

class MitreMapper:
    """High-Performance Deterministic MITRE ATT&CK Mapper."""

    def __init__(self):
        # A list of tuples (Regex Pattern, MitreTechnique)
        # Order matters: more specific patterns should come first.
        self.rules = [
            # T1548: Privilege Escalation
            (
                re.compile(r'(?i)(sudo\s+|su\s+-|pkexec|/etc/sudoers)'),
                MitreTechnique(
                    tactic_id="TA0004",
                    tactic_name="Privilege Escalation",
                    technique_id="T1548",
                    technique_name="Abuse Elevation Control Mechanism",
                    subtechnique_id="T1548.003"
                )
            ),
            # T1222: Defense Evasion
            (
                re.compile(r'(?i)(chmod\s+\+x|chmod\s+777|chown)'),
                MitreTechnique(
                    tactic_id="TA0005",
                    tactic_name="Defense Evasion",
                    technique_id="T1222",
                    technique_name="File and Directory Permissions Modification",
                    subtechnique_id="T1222.002"
                )
            ),
            # T1053: Persistence
            (
                re.compile(r'(?i)(auth_cron|crontab|/etc/cron\.\S*)'),
                MitreTechnique(
                    tactic_id="TA0003",
                    tactic_name="Persistence",
                    technique_id="T1053",
                    technique_name="Scheduled Task/Job",
                    subtechnique_id="T1053.003"
                )
            ),
            # T1486: Impact
            (
                re.compile(r'(?i)(?:^|\W)(encrypt|donotcry|wannacry|ransom|openssl\s+enc|gpg\s+-c)(?:\W|$)'),
                MitreTechnique(
                    tactic_id="TA0040",
                    tactic_name="Impact",
                    technique_id="T1486",
                    technique_name="Data Encrypted for Impact"
                )
            ),
            # T1490: Impact
            (
                re.compile(r'(?i)(vssadmin\s+delete|shadowcopy|bcdedit|wbadmin)'),
                MitreTechnique(
                    tactic_id="TA0040",
                    tactic_name="Impact",
                    technique_id="T1490",
                    technique_name="Inhibit System Recovery"
                )
            ),
            # T1003: Credential Access
            (
                re.compile(r'(?i)(/etc/shadow|mimikatz|lsass|secretsdump)'),
                MitreTechnique(
                    tactic_id="TA0006",
                    tactic_name="Credential Access",
                    technique_id="T1003",
                    technique_name="OS Credential Dumping"
                )
            ),
            # T1087: Discovery
            (
                re.compile(r'(?i)(?:^|\W)(whoami|id|net\s+user|getent\s+passwd)(?:\W|$)'),
                MitreTechnique(
                    tactic_id="TA0007",
                    tactic_name="Discovery",
                    technique_id="T1087",
                    technique_name="Account Discovery"
                )
            ),
            # T1105: C2
            (
                re.compile(r'(?i)(?:^|\W)(curl|wget|http://|https://|ftp://|bitsadmin|Invoke-WebRequest|certutil\s+-urlcache)(?:\W|$)'),
                MitreTechnique(
                    tactic_id="TA0011",
                    tactic_name="Command and Control",
                    technique_id="T1105",
                    technique_name="Ingress Tool Transfer"
                )
            ),
            # T1106: Native API Execution
            (
                re.compile(r'(?i)(/lib64/ld-linux\S*|ld\.so)'),
                MitreTechnique(
                    tactic_id="TA0002",
                    tactic_name="Execution",
                    technique_id="T1106",
                    technique_name="Native API"
                )
            ),
            # T1059: Execution (Bash/Sh)
            (
                re.compile(r'(?i)(/bin/bash|/bin/sh|\|\s*bash|eval\s+|sh\s+-c)'),
                MitreTechnique(
                    tactic_id="TA0002",
                    tactic_name="Execution",
                    technique_id="T1059",
                    technique_name="Command and Scripting Interpreter",
                    subtechnique_id="T1059.004"
                )
            ),
            # T1059: Execution (PowerShell)
            (
                re.compile(r'(?i)(?:^|\W)(powershell\.exe|pwsh|\.ps1|-enc|IEX|DownloadString)(?:\W|$)'),
                MitreTechnique(
                    tactic_id="TA0002",
                    tactic_name="Execution",
                    technique_id="T1059",
                    technique_name="Command and Scripting Interpreter",
                    subtechnique_id="T1059.001"
                )
            ),
        ]

    def classify_event(self, action: str, metadata: Optional[Dict] = None) -> Optional[MitreTechnique]:
        """Classifies an event string or metadata dictionary to a MITRE ATT&CK technique."""
        # 1. Step 1: Check SIEM Metadata (Wazuh / Suricata tags)
        if metadata:
            # Example: check if metadata has 'mitre_technique' or something similar
            mitre_info = metadata.get("mitre", {})
            if "id" in mitre_info:
                # E.g., Wazuh often provides rule.mitre.id
                pass # This could be expanded based on specific SIEM schema

        # 2. Step 2: Deterministic Rule Matrix (Regex & Command Tokenizer)
        if action:
            for pattern, technique in self.rules:
                if pattern.search(action):
                    logger.debug(f"Mapped '{action}' to {technique.technique_id} via regex.")
                    return technique
                    
        return None

mitre_mapper = MitreMapper()
