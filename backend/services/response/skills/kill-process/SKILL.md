---
name: kill-process
description: Terminates malicious process instances and associated child process trees on endpoints.
version: 1.0.0
phase: response
inputs:
  - name: process_name
    type: string
    description: Process name, executable path, or PID to terminate
  - name: target_host
    type: string
    description: Hostname where the process is running
outputs:
  - name: action_status
    type: string
    description: Execution result status
  - name: terminated_pids
    type: array
    description: List of PIDs terminated
mitre_attack:
  - T1059
  - T1204
nist_csf:
  - RS.MI
---

# Kill Process Response Skill

## Overview
Issues SIGKILL/taskkill commands to terminate active malware processes, ransomware encryptors, or unauthorized shell sessions on target endpoints.
