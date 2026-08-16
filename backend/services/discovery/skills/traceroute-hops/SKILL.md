---
name: traceroute-hops
description: Trace network path to determine hop count and route
collects:
  - hop_count
  - hops
  - ttl
method: command
commandTemplate: tracert -d -w 2000 -h 15 {{ip}}
commandTemplateFallback: traceroute -n -w 2 -m 15 {{ip}}
requires:
  bins:
    - tracert
---

# Parsing Instructions

## Windows tracert Output
- Lines starting with a number are hops: "  1    <1 ms   <1 ms    1 ms  192.168.1.1"
- Count numbered lines = hop_count
- Last hop number = ttl

## Linux traceroute Output
- Lines starting with a number are hops: " 1  192.168.1.1 (192.168.1.1)  0.5 ms"
- Count numbered lines = hop_count
- "*" entries = unresponsive hops (still count)
