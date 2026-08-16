---
name: wmi-os-info
description: Collect OS name, version, and build via WMI (Windows only)
collects:
  - os_name
  - os_version
  - os_build
method: command
platform: win32
commandTemplate: powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress"
requires:
  bins:
    - powershell
---

# Parsing Instructions

## JSON Output
```json
{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22631","BuildNumber":"22631"}
```
- Caption → os_name
- Version → os_version
- BuildNumber → os_build
