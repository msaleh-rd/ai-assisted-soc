---
name: persistence-auditor
phase: evidence
description: Audits host persistence mechanisms including Windows Registry Run keys, Scheduled Tasks, Linux systemd services, cron jobs, SSH authorized_keys, and WMI event subscriptions.
collects:
  - scheduled_tasks
  - cron_jobs
  - registry_run_keys
  - systemd_services
  - autorun_entries
actions:
  - inspect_persistence_mechanisms
  - detect_startup_anomalies
method: handler
parameters:
  host_id:
    type: string
    description: Target host ID or computer name
---

# Persistence Auditor Skill

## Purpose
Discovers stealthy persistence established by attackers to maintain access across reboots, including modified cron scripts (e.g. `healthcheck_cron.sh`), new administrative services, or registry autostart keys.

## Outputs
- Newly created cron jobs or scheduled tasks within the incident window
- Registry Run / RunOnce modifications
- Unknown services set to start automatically
