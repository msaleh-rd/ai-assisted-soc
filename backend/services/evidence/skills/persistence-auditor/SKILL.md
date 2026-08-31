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
mitre_attack:
  - T1053
  - T1053.003
  - T1543
  - T1547
nist_csf:
  - DE.CM
  - DE.AE
parameters:
  host_id:
    type: string
    description: Target host ID or computer name
---

# Persistence Auditor Skill

## Purpose
Discovers stealthy persistence established by attackers to maintain access across reboots, including modified cron scripts (e.g. `healthcheck_cron.sh`), new administrative services, or registry autostart keys.

## Underlying Persistence Inspection Queries
When scanning host `{{host_id}}` for autostart and persistence artifacts:

```bash
# Linux cron jobs and systemd timer services
crontab -l
cat /etc/crontab /etc/cron.d/* /etc/cron.daily/*
systemctl list-timers --all

# Windows Scheduled Tasks & Run keys (PowerShell)
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, TaskPath
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

## Outputs
- Newly created cron jobs or scheduled tasks within the incident window
- Registry Run / RunOnce modifications
- Unknown services set to start automatically
