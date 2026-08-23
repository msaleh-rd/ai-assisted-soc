---
name: ioc-extractor
phase: triage
description: Deep extraction and identification of Indicators of Compromise (IPs, hashes, files, processes, domains, users, URLs, registry keys) from raw security alerts and vendor payloads.
collects:
  - entities
  - iocs
  - users
  - hosts
  - ips
  - files
  - processes
  - domains
method: handler
parameters:
  raw_alert:
    type: object
    description: The full raw alert payload
---

# IOC Extractor Skill

## Purpose
Extracts all actionable security indicators (users, hosts, IP addresses, filenames, hashes, processes, and domains) from unstructured text, syslog strings, or vendor-specific telemetry dictionaries (CrowdStrike, Splunk, Wazuh, Suricata, AWS GuardDuty).

## Guidelines
- Extract entity values verbatim without modification.
- Tag entity types strictly using the standard SOC taxonomy: `user`, `host`, `ip`, `file`, `process`, `domain`, `registry`.
- Eliminate duplicate entities.
