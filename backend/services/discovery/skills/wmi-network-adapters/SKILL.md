---
name: wmi-network-adapters
description: Collect network adapter info including MAC addresses (Windows only)
collects:
  - mac_address
  - adapter_name
  - network_adapters
method: command
platform: win32
commandTemplate: powershell -NoProfile -Command "Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object Description,MACAddress | ConvertTo-Json -Compress"
requires:
  bins:
    - powershell
---

# Parsing Instructions

## JSON Output
```json
[{"Description":"Intel(R) Wi-Fi 6E","MACAddress":"A4:B1:C2:D3:E4:F5"}]
```
- First entry's MACAddress → mac_address
- First entry's Description → adapter_name
- Array length → network_adapters count
