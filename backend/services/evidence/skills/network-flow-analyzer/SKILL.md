---
name: network-flow-analyzer
phase: evidence
description: Analyzes network connections, NetFlow telemetry, active socket sessions, beaconing intervals, and external communication volumes for host and IP entities.
collects:
  - network_connections
  - c2_beacons
  - open_sockets
  - traffic_volume
  - destination_ips
actions:
  - trace_outbound_connections
  - detect_c2_beaconing
method: handler
parameters:
  target_ip_or_host:
    type: string
    description: IP address or hostname to analyze
---

# Network Flow Analyzer Skill

## Purpose
Examines network telemetry associated with an entity to discover C2 channels, data exfiltration pipelines, lateral movement connections (SMB 445, RDP 3389, SSH 22), and unusual port activity.

## Outputs
- Outbound destination IP addresses and ports
- Bytes transferred in/out
- Beaconing regularity score
- Protocol breakdown (HTTP/HTTPS, SSH, DNS, SMB)
