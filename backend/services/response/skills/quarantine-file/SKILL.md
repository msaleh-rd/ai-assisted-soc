---
name: quarantine-file
description: Moves a malicious or suspicious file into a secure quarantine location and prevents further execution, without deleting it so it remains available for forensic analysis.
version: 1.0.0
phase: response
method: handler
actions:
  - quarantine_target_file
parameters:
  target_file:
    type: string
    description: Absolute file path or file hash (SHA256) of the file to quarantine
mitre_attack:
  - T1204
  - T1105
nist_csf:
  - PR.DS
  - RS.MI
---

# Quarantine File Response Skill

## Overview
Isolates a malicious or suspicious file by moving it to a restricted quarantine directory and stripping execute permissions, preserving the artifact for forensic review while neutralizing the immediate threat. This is a low blast-radius, reversible action.

## Containment Commands
When executed on `{{target_file}}`, this skill models file quarantine:

```bash
# Linux quarantine
mkdir -p /var/quarantine
mv "{{target_file}}" /var/quarantine/
chmod 000 "/var/quarantine/$(basename "{{target_file}}")"

# Windows quarantine (PowerShell)
New-Item -ItemType Directory -Force -Path "C:\Quarantine"
Move-Item -Path "{{target_file}}" -Destination "C:\Quarantine\"
icacls "C:\Quarantine\$(Split-Path "{{target_file}}" -Leaf)" /deny Everyone:F
```

## Rollback Commands
To restore the file from quarantine:

```bash
# Linux restore
chmod 644 "/var/quarantine/$(basename "{{target_file}}")"
mv "/var/quarantine/$(basename "{{target_file}}")" "{{target_file}}"

# Windows restore (PowerShell)
icacls "C:\Quarantine\$(Split-Path "{{target_file}}" -Leaf)" /reset
Move-Item -Path "C:\Quarantine\$(Split-Path "{{target_file}}" -Leaf)" -Destination "{{target_file}}"
```
