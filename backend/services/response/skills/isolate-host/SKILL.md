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

## Containment Commands
When executed on target `{{target_host}}`, this skill models firewall rules to block all traffic except EDR/Management telemetry:

```bash
# Allow established connections to management / EDR server
iptables -A INPUT -s {{edr_management_ip}} -j ACCEPT
iptables -A OUTPUT -d {{edr_management_ip}} -j ACCEPT

# Drop all other traffic on {{target_host}}
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
```

## Rollback Commands
To reverse the containment on `{{target_host}}` and restore normal network operations:

```bash
# Flush rules and restore default ACCEPT policy
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
```
