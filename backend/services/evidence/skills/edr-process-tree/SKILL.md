---
name: edr-process-tree
phase: evidence
description: Queries EDR process telemetry to reconstruct parent-child PID execution trees, command-line arguments, spawned binaries, and DLL load events on compromised hosts.
collects:
  - process_tree
  - parent_process
  - child_processes
  - command_lines
  - pid_ancestry
actions:
  - query_process_ancestry
  - find_child_processes
method: handler
mitre_attack:
  - T1059
  - T1059.004
  - T1106
  - T1204
nist_csf:
  - DE.CM
  - DE.AE
parameters:
  host_id:
    type: string
    description: Target host identifier or computer name
  process_name_or_pid:
    type: string
    description: Process name or PID to expand
---

# EDR Process Tree Skill

## Purpose
Collects the full execution hierarchy around a suspicious process or script (e.g. `bash` -> `curl` -> `install.sh` -> `donotcry` or `cmd.exe` -> `powershell.exe -enc`).

## Underlying Forensic Commands & Queries
When querying live endpoints or Linux audit telemetry on host `{{host_id}}`, this skill models:

```bash
# Linux auditd execve and process ancestry
ausearch -m execve -c "{{process_name_or_pid}}" --format text

# Process tree hierarchy (Linux)
pstree -p -a {{process_name_or_pid}}

# Windows EDR process line (PowerShell)
Get-CimInstance Win32_Process | Where-Object { $_.Name -match "{{process_name_or_pid}}" -or $_.ProcessId -eq "{{process_name_or_pid}}" } | Select-Object ProcessId, ParentProcessId, CommandLine
```

## Outputs
- Parent process name and PID
- Exact CLI arguments executed
- Spawned child binaries
- User context under which the process ran
