---
name: port-scan-basic
description: Quick TCP port scan for common services (top 20 ports)
collects:
  - open_ports
  - ports
  - listening_services
  - services
method: command
commandTemplate: powershell -NoProfile -Command "$ports=@(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080); $results=@(); foreach($p in $ports){$c=New-Object Net.Sockets.TcpClient; try{$c.Connect('{{ip}}',$p); if($c.Connected){$results+=$p}; $c.Close()}catch{}}; $results -join [char]10"
commandTemplateFallback: bash -c 'for p in 21 22 23 25 53 80 110 135 139 143 443 445 993 995 3306 3389 5900 8080; do (echo >/dev/tcp/{{ip}}/$p) 2>/dev/null && echo $p; done'
requires:
  bins:
    - powershell
---

# Parsing Instructions

## PowerShell Output
- Each line is an open port number (e.g. "80\n443\n3389")
- Collect all numbers as open_ports (comma-separated)

## nmap grepable Output
- Line with "Ports:" contains open ports in format: PORT/STATE/PROTO//SERVICE//
- e.g. "80/open/tcp//http//, 443/open/tcp//https//"
- Extract port numbers and service names
