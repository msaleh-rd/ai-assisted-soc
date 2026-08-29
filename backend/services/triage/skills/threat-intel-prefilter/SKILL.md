---
name: threat-intel-prefilter
description: Rapid IOC pre-filtering against local Threat Intelligence cache and reputation feeds during alert ingestion.
version: 1.0.0
phase: triage
inputs:
  - name: entities
    type: object
    description: Extracted entities (IPs, domains, hashes)
outputs:
  - name: flagged_iocs
    type: array
    description: List of IOCs with immediate high-confidence malicious verdicts
mitre_attack:
  - T1583
  - T1584
nist_csf:
  - ID.RA
  - DE.CM
---

# Threat Intel Pre-Filter Skill

## Overview
Executes lightweight threat intelligence checks on initial alert entities to flag known malicious IOCs before deep forensic expansion.
