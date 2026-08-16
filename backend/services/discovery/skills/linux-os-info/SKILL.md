---
name: linux-os-info
description: Collect OS info from /etc/os-release and uname (Linux only)
collects:
  - os_name
  - os_version
  - distro
  - kernel_version
method: command
platform: linux
commandTemplate: cat /etc/os-release 2>/dev/null; echo "---"; uname -r
requires:
  bins:
    - cat
    - uname
---

# Parsing Instructions

## Output Format
```
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
---
6.5.0-35-generic
```
- PRETTY_NAME → os_name, distro
- VERSION_ID → os_version
- After "---" → kernel_version
