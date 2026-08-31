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

## Containment Commands
When executed, this skill injects firewall drop rules for `{{target_ip}}`:

```bash
# Linux iptables block
iptables -I INPUT -s {{target_ip}} -j DROP
iptables -I OUTPUT -d {{target_ip}} -j DROP

# Windows Firewall block
netsh advfirewall firewall add rule name="SOC_Block_{{target_ip}}" dir=in action=block remoteip={{target_ip}}
netsh advfirewall firewall add rule name="SOC_Block_{{target_ip}}" dir=out action=block remoteip={{target_ip}}
```

## Rollback Commands
To unblock the IP address:

```bash
# Linux iptables unblock
iptables -D INPUT -s {{target_ip}} -j DROP
iptables -D OUTPUT -d {{target_ip}} -j DROP

# Windows Firewall unblock
netsh advfirewall firewall delete rule name="SOC_Block_{{target_ip}}"
```
