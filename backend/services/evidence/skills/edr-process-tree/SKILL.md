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

## Outputs
- Parent process name and PID
- Exact CLI arguments executed
- Spawned child binaries
- User context under which the process ran
