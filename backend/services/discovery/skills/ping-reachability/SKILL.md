---
name: ping-reachability
description: Check if a host responds to ICMP echo (ping)
collects:
  - reachability
  - latency
  - rtt
method: command
commandTemplate: ping -n 3 -w 2000 {{ip}}
commandTemplateFallback: ping -c 3 -W 2 {{ip}}
requires:
  bins:
    - ping
---

# Parsing Instructions

## Windows Output
- "Reply from X.X.X.X" → reachability = icmp_ok
- "Request timed out" / "100% loss" → reachability = unreachable
- "Average = Xms" → latency = X

## Linux Output
- "bytes from" → reachability = icmp_ok
- "100% packet loss" → reachability = unreachable
- "rtt min/avg/max/mdev = .../X/..." → latency = avg value
