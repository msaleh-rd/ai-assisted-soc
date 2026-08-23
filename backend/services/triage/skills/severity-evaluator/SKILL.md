---
name: severity-evaluator
phase: triage
description: Dynamically assesses alert severity level (Critical, High, Medium, Low) based on asset criticality, exploitability, attacker capabilities, and containment urgency.
collects:
  - severity
  - requires_immediate_action
  - risk_level
method: handler
parameters:
  alert_data:
    type: object
    description: Alert indicators and affected entities
---

# Severity Evaluator Skill

## Purpose
Evaluates whether an incident poses immediate existential risk to the organization (e.g. Domain Controller compromise, active ransomware encryption, unauthenticated remote code execution) or is a low-impact informational event.

## Rating Scale
- **Critical**: Active ransomware, widespread compromise, Domain Admin credential dump, active exfiltration.
- **High**: Malware execution on production servers, successful credential access, lateral movement attempts.
- **Medium**: Suspicious script on non-critical endpoint, blocked external scan, single failed brute force.
- **Low / Informational**: Policy violation, benign software update anomaly, noisy threshold alert.
