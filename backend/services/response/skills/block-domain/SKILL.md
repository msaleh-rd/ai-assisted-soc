---
name: block-domain
description: Sinkholes malicious domain names in internal DNS resolvers and adds web proxy blacklists.
version: 1.0.0
phase: response
method: handler
actions:
  - sinkhole_target_domain
parameters:
  target_domain:
    type: string
    description: FQDN of the malicious domain
mitre_attack:
  - T1568
  - T1071.004
nist_csf:
  - PR.PT
  - RS.MI
---

# Block Domain Response Skill

## Overview
Redirects DNS queries for malicious domains to an internal sinkhole IP and applies URL filtering across proxy gateways.
