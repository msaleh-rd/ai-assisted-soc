---
name: block-ip
description: Blocks an external or internal malicious IP address across perimeter firewalls and local host firewalls.
version: 1.0.0
phase: response
method: handler
actions:
  - block_target_ip
parameters:
  target_ip:
    type: string
    description: IPv4 or IPv6 address to block
mitre_attack:
  - T1071
  - T1571
nist_csf:
  - PR.AC
  - RS.MI
---

# Block IP Response Skill

## Overview
Injects blocking rules into edge perimeter firewalls and host iptables to sever active connections to malicious C2 infrastructure or attacker pivots.
