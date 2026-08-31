---
name: isolate-host
description: Isolates a compromised endpoint from the network by restricting inbound and outbound traffic while maintaining EDR connectivity.
version: 1.0.0
phase: response
method: handler
actions:
  - restrict_host_network
parameters:
  target_host:
    type: string
    description: Hostname or IP address of the target machine to isolate
mitre_attack:
  - T1048
  - T1567
nist_csf:
  - RS.MI
  - RS.CO
---

# Isolate Host Response Skill

## Overview
Restricts network access on a target endpoint via iptables or EDR agent isolation to prevent lateral movement and C2 communications during an active incident.
