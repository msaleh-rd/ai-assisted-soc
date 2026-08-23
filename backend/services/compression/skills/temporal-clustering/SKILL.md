---
name: temporal-clustering
phase: compression
description: Groups raw security telemetry events into coherent incident clusters based on sliding temporal windows and event time-proximity relative to the primary trigger timestamp.
collects:
  - time_windows
  - clustered_events
  - attack_duration
actions:
  - cluster_by_time_window
  - align_incident_timeline
method: statistical
parameters:
  window_seconds:
    type: integer
    default: 1800
    description: Time window delta in seconds for clustering
---

# Temporal Clustering Skill

## Purpose
Clusters log streams into discrete temporal phases (Pre-attack reconnaissance, Ingress execution, Lateral movement, Exfiltration/Impact), filtering out unrelated logs that occurred far outside the active attack window.

## Outputs
- Grouped event clusters by phase
- Incident start, peak, and containment timestamps
- Time-decay weighted event relevance scores
