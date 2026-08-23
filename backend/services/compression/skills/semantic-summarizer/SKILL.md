---
name: semantic-summarizer
phase: compression
description: Abstracts low-level log lines and event clusters into high-level human-readable narrative attack milestones and chronological timeline sequences.
collects:
  - abstracted_timeline
  - attack_milestones
  - incident_summary
actions:
  - abstract_event_stream
  - generate_timeline_summary
method: handler
parameters:
  max_timeline_items:
    type: integer
    default: 10
    description: Maximum number of chronological milestone items
---

# Semantic Summarizer Skill

## Purpose
Translates technical low-level log entries (e.g. `sys_execve(install.sh)`, `iptables -A`, `curl 192.42.1.174:8888`) into actionable, executive-level incident milestones mapped to attack progression stages.

## Outputs
- Clean chronological timeline objects (`timestamp`, `title`, `description`, `severity`, `entities_involved`)
- Executive incident progression summary
