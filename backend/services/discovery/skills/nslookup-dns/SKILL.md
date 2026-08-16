---
name: nslookup-dns
description: Reverse DNS lookup to find hostname for an IP address
collects:
  - hostname
  - dns_name
  - fqdn
  - reverse_dns
method: command
commandTemplate: nslookup {{ip}}
commandTemplateFallback: host {{ip}}
requires:
  bins:
    - nslookup
---

# Parsing Instructions

## nslookup Output
- "Name: hostname.domain.com" → hostname = hostname.domain.com
- Look for lines after "Non-authoritative answer:"
- "name = host.domain.com" (PTR record) → reverse_dns

## host Output (Linux fallback)
- "X.X.X.X.in-addr.arpa domain name pointer host.domain.com" → hostname
