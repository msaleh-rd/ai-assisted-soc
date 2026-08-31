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
mitre_attack:
  - T1071
  - T1048
  - T1571
nist_csf:
  - DE.CM
  - DE.AE
parameters:
  target_ip_or_host:
    type: string
    description: IP address or hostname to analyze
---

# Network Flow Analyzer Skill

## Purpose
Examines network telemetry associated with an entity to discover C2 channels, data exfiltration pipelines, lateral movement connections (SMB 445, RDP 3389, SSH 22), and unusual port activity.

## Underlying Network Telemetry Queries
When inspecting active sockets and network flows for `{{target_ip_or_host}}`:

```bash
# Linux active socket connections and listening ports
ss -tunap | grep "{{target_ip_or_host}}"
netstat -antp | grep "{{target_ip_or_host}}"

# Suricata / Zeek flow logs (jq / ripgrep)
jq -r 'select(.src_ip=="{{target_ip_or_host}}" or .dest_ip=="{{target_ip_or_host}}")' /var/log/suricata/eve.json
```

## Outputs
- Outbound destination IP addresses and ports
- Bytes transferred in/out
- Beaconing regularity score
- Protocol breakdown (HTTP/HTTPS, SSH, DNS, SMB)
