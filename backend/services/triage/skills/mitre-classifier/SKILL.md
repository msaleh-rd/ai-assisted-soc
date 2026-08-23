---
name: mitre-classifier
phase: triage
description: Classifies security alerts into standardized incident categories and maps them to MITRE ATT&CK tactics (e.g. Initial Access, Execution, Persistence, Lateral Movement, Exfiltration) and technique IDs.
collects:
  - classification
  - tactic
  - technique
  - mitre_attack
method: handler
parameters:
  alert_data:
    type: object
    description: Alert event type, description, and metadata
---

# MITRE Classifier Skill

## Purpose
Analyzes the alert trigger conditions, command lines, and vendor tags to determine the MITRE ATT&CK Matrix alignment and primary classification category.

## Categories Supported
- `malware_execution`: Ransomware, trojans, suspicious scripts, binary drops.
- `lateral_movement`: PsExec, SSH pivoting, SMB remote file execution, pass-the-hash.
- `credential_access`: Mimikatz, LSASS memory dump, brute force, credential stuffing.
- `data_exfiltration`: Large outbound transfers, cloud sync anomalies, archive creation.
- `command_and_control`: C2 beaconing, DNS tunneling, reverse shells.
- `persistence`: Registry run keys, scheduled tasks, cron jobs, service creation.
