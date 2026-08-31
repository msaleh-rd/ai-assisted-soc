---
name: file-forensics
phase: evidence
description: Gathers cryptographic hashes (MD5, SHA256), entropy analysis, digital certificate signing status, file modification timestamps, and ransom note extensions.
collects:
  - file_hashes
  - entropy_score
  - signature_status
  - file_size
  - creation_time
  - ransom_indicators
actions:
  - analyze_file_metadata
  - check_ransomware_patterns
method: handler
mitre_attack:
  - T1486
  - T1027
  - T1036
  - T1105
nist_csf:
  - DE.AE
  - DE.CM
parameters:
  file_path_or_hash:
    type: string
    description: Absolute file path, filename, or hash to analyze
---

# File Forensics Skill

## Purpose
Inspects file entities dropped or executed during an incident to detect encryption activity (high entropy), unsigned binaries masquerading as system files, or known ransomware payload signatures.

## Outputs
- SHA256 / MD5 hashes
- Entropy calculation (> 7.5 indicates encrypted or packed payload)
- Digital signature verification
- Target file directory and permissions
