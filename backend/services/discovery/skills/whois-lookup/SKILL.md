---
name: whois-lookup
description: WHOIS lookup for IP ownership and organization info
collects:
  - organization
  - country
  - net_range
  - net_description
method: command
commandTemplate: powershell -NoProfile -Command "(Invoke-WebRequest -Uri 'https://whois.arin.net/rest/ip/{{ip}}.txt' -UseBasicParsing).Content"
commandTemplateFallback: whois {{ip}}
requires:
  bins:
    - powershell
---

# Parsing Instructions

## ARIN REST Output / whois Output
- "OrgName:" or "Organization:" → organization
- "Country:" → country
- "NetRange:" or "inetnum:" → net_range
- "NetName:" or "descr:" → net_description
