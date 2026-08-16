"""Discovery agent - executes skills against targets and collects attributes."""

import asyncio
import os
import subprocess
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from backend.services.discovery.skill_loader import Skill, SkillLoader


# Input validation patterns
IPV4_RE = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}$')

# Blocked commands (security)
BLOCKED_PATTERNS = [
    re.compile(r'rm\s+-rf\s+/', re.IGNORECASE),
    re.compile(r'format\s+[a-z]:', re.IGNORECASE),
    re.compile(r'Remove-Item\s+.*-Recurse', re.IGNORECASE),
    re.compile(r'del\s+/[sfq]', re.IGNORECASE),
]

COMMAND_TIMEOUT = 30  # seconds
MAX_OUTPUT = 64 * 1024  # 64KB


@dataclass
class DiscoveryResult:
    """Result of discovering attributes for a single host."""
    target: str
    status: str  # alive, unreachable, unknown, error
    attributes: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    raw_outputs: Dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TopologyEntry:
    """A host entry for topology merge."""
    ip: str
    status: str
    attributes: Dict[str, Any]
    provenance: Dict[str, str]


@dataclass
class DiscoveryScanResult:
    """Complete result of a discovery scan."""
    scan_id: str
    targets: List[str]
    requested_attributes: List[str]
    skills_used: List[str]
    hosts: List[DiscoveryResult]
    topology: List[TopologyEntry]
    started_at: str
    completed_at: str
    duration_seconds: float


class DiscoveryAgent:
    """
    Executes discovery skills against target hosts to collect attributes.
    
    Workflow:
    1. Match requested attributes to available skills
    2. For each target, execute matched skills
    3. Parse output according to skill instructions
    4. Build topology from results
    """

    def __init__(self, skills_dir: Optional[str] = None):
        self.loader = SkillLoader(skills_dir)
        self.is_windows = platform.system() == 'Windows'
        self.in_docker = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')

    async def discover(
        self,
        targets: List[str],
        attributes: List[str],
        timeout: int = COMMAND_TIMEOUT
    ) -> DiscoveryScanResult:
        """
        Run discovery against targets for requested attributes.
        
        Args:
            targets: List of IPs or hostnames to discover
            attributes: List of attribute names to collect
            timeout: Command timeout in seconds
            
        Returns:
            Complete scan result with topology
        """
        import uuid
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        started_at = datetime.now()

        # Validate targets
        validated_targets = [t for t in targets if self._validate_target(t)]

        # In Docker, translate localhost/127.0.0.1 to the Docker host
        # Keep a mapping so results show the original target name
        original_targets = {t: t for t in validated_targets}
        if self.in_docker:
            resolved = []
            for t in validated_targets:
                r = self._resolve_docker_target(t)
                original_targets[r] = t
                resolved.append(r)
            validated_targets = resolved

        # Find skills for requested attributes
        matched_skills = self.loader.find_skills_for_attributes(attributes)
        skills_used = [s.name for s in matched_skills]

        # Execute discovery for each target
        hosts = []
        for target in validated_targets:
            result = await self._discover_host(target, attributes, matched_skills, timeout)
            # Restore the original target name the user typed
            result.target = original_targets.get(target, target)
            hosts.append(result)

        completed_at = datetime.now()
        duration = (completed_at - started_at).total_seconds()

        # Build topology
        topology = [
            TopologyEntry(
                ip=h.target,
                status=h.status,
                attributes=h.attributes,
                provenance=h.provenance,
            )
            for h in hosts
        ]

        return DiscoveryScanResult(
            scan_id=scan_id,
            targets=targets,
            requested_attributes=attributes,
            skills_used=skills_used,
            hosts=hosts,
            topology=topology,
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            duration_seconds=duration,
        )

    async def _discover_host(
        self,
        target: str,
        attributes: List[str],
        skills: List[Skill],
        timeout: int
    ) -> DiscoveryResult:
        """Discover attributes for a single host."""
        result = DiscoveryResult(target=target, status="unknown")

        for skill in skills:
            # Skip platform-specific skills on wrong OS
            if skill.platform == 'win32' and not self.is_windows:
                continue
            if skill.platform == 'linux' and self.is_windows:
                continue

            # Skills that read local system info (OS, adapters) only work
            # on the machine running the scanner, not remote targets.
            # In Docker, host.docker.internal is NOT local (it's the host).
            LOCAL_ONLY_SKILLS = {'linux-os-info', 'wmi-os-info', 'wmi-network-adapters'}
            if skill.name in LOCAL_ONLY_SKILLS:
                is_local = target in ('127.0.0.1', 'localhost', '::1')
                if not is_local:
                    continue

            # Check which attributes this skill provides that we still need
            needed = [a for a in attributes if a not in result.attributes]
            can_collect = skill.matches_attributes(needed)
            if not can_collect:
                continue

            # Execute the skill
            output, error = await self._execute_skill(skill, target, timeout)

            if error:
                result.errors.append(f"{skill.name}: {error}")
                # Don't mark as unavailable yet — native probes may fill in
                continue

            # Store raw output for parsing
            result.raw_outputs[skill.name] = output

            # Parse output according to skill
            parsed = self._parse_skill_output(skill, output, target)

            for attr, value in parsed.items():
                if attr in attributes:
                    result.attributes[attr] = value
                    result.provenance[attr] = skill.name

            # Update host status based on reachability
            if 'reachability' in parsed:
                if parsed['reachability'] in ('icmp_ok', 'alive', 'reachable', 'tcp_ok', 'tcp_rst'):
                    result.status = 'alive'
                elif parsed['reachability'] in ('unreachable', 'timeout'):
                    result.status = 'unreachable'

        # Use Python-native probes for any attributes still missing or unknown
        missing = [a for a in attributes
                   if a not in result.attributes
                   or result.attributes[a] in ('unavailable', 'unknown', '')]
        if missing:
            try:
                from backend.services.discovery.native_probes import run_native_discovery
                native_attrs, native_prov = await run_native_discovery(
                    target, missing, timeout=min(timeout, 10)
                )
                for attr, value in native_attrs.items():
                    if attr not in result.attributes or result.attributes[attr] in ('unavailable', 'unknown', ''):
                        result.attributes[attr] = value
                        result.provenance[attr] = native_prov.get(attr, 'python_native')

                # Update status from native reachability
                reach = native_attrs.get('reachability', '')
                if reach in ('tcp_ok', 'tcp_rst') and result.status == 'unknown':
                    result.status = 'alive'
                elif reach == 'unreachable' and result.status == 'unknown':
                    result.status = 'unreachable'
            except Exception:
                pass  # Native probes are best-effort

        # Mark any remaining requested attributes as unavailable
        for attr in attributes:
            if attr not in result.attributes:
                result.attributes[attr] = "unavailable"
                result.provenance[attr] = "no_skill_match"

        return result

    async def _execute_skill(
        self,
        skill: Skill,
        target: str,
        timeout: int
    ) -> Tuple[str, Optional[str]]:
        """Execute a skill's command template against a target."""
        values = {'ip': target, 'target': target, 'host': target}

        # On Linux, prefer fallback command (which uses Linux tools)
        # On Windows, prefer primary command
        use_fallback = not self.is_windows and skill.command_template_fallback
        command = skill.render_command(values, use_fallback=bool(use_fallback))

        if not command:
            # If no fallback available on Linux, try the primary anyway
            command = skill.render_command(values, use_fallback=False)
            if not command:
                return "", "No command template for this platform"

        # Security check
        if self._is_blocked(command):
            return "", "Command blocked by security policy"

        # Execute
        try:
            output = await self._run_command(command, timeout)
            if output.strip():
                return output, None
            # If primary produced no output, try fallback
            if not use_fallback and skill.command_template_fallback:
                fallback_cmd = skill.render_command(values, use_fallback=True)
                if fallback_cmd and not self._is_blocked(fallback_cmd):
                    output = await self._run_command(fallback_cmd, timeout)
                    return output, None
            return output, None
        except asyncio.TimeoutError:
            # Try the other template on timeout
            alt_cmd = skill.render_command(values, use_fallback=not use_fallback)
            if alt_cmd and alt_cmd != command and not self._is_blocked(alt_cmd):
                try:
                    output = await self._run_command(alt_cmd, timeout)
                    return output, None
                except Exception as e:
                    return "", f"Both commands failed: {str(e)}"
            return "", "Command timed out"
        except Exception as e:
            # Try fallback on error
            alt_cmd = skill.render_command(values, use_fallback=not use_fallback)
            if alt_cmd and alt_cmd != command and not self._is_blocked(alt_cmd):
                try:
                    output = await self._run_command(alt_cmd, timeout)
                    return output, None
                except Exception:
                    pass
            return "", str(e)

    async def _run_command(self, command: str, timeout: int) -> str:
        """Run a shell command and return output."""
        # Detect if this is a PowerShell command
        is_ps_command = command.strip().startswith('powershell') or \
                       command.strip().startswith('Get-') or \
                       'ConvertTo-Json' in command

        if self.is_windows or is_ps_command:
            if is_ps_command and not command.strip().startswith('powershell'):
                args = ['powershell.exe', '-NoProfile', '-Command', command]
            else:
                args = ['powershell.exe', '-NoProfile', '-Command', command]
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        output = stdout.decode('utf-8', errors='replace')[:MAX_OUTPUT]
        if proc.returncode != 0 and not output.strip():
            err_output = stderr.decode('utf-8', errors='replace')[:MAX_OUTPUT]
            if err_output:
                output = err_output

        return output

    def _parse_skill_output(
        self,
        skill: Skill,
        output: str,
        target: str
    ) -> Dict[str, Any]:
        """Parse command output based on skill type and attributes."""
        parsed = {}

        if skill.name == 'ping-reachability':
            parsed.update(self._parse_ping(output))
        elif skill.name == 'nslookup-dns':
            parsed.update(self._parse_nslookup(output))
        elif skill.name == 'port-scan-basic':
            parsed.update(self._parse_portscan(output))
        elif skill.name == 'traceroute-hops':
            parsed.update(self._parse_traceroute(output))
        elif skill.name in ('wmi-os-info', 'linux-os-info'):
            parsed.update(self._parse_os_info(output))
        elif skill.name == 'wmi-network-adapters':
            parsed.update(self._parse_network_adapters(output))
        elif skill.name == 'whois-lookup':
            parsed.update(self._parse_whois(output))
        else:
            # Generic: try to extract key-value pairs
            parsed.update(self._parse_generic(output, skill.collects))

        return parsed

    def _parse_ping(self, output: str) -> Dict[str, Any]:
        """Parse ping output for reachability and latency."""
        result = {}
        lower = output.lower()

        # Check reachability
        if 'reply from' in lower or 'bytes from' in lower:
            result['reachability'] = 'icmp_ok'
        elif '100% packet loss' in lower or 'request timed out' in lower:
            result['reachability'] = 'unreachable'
        elif 'destination host unreachable' in lower:
            result['reachability'] = 'unreachable'
        else:
            result['reachability'] = 'unknown'

        # Extract latency
        avg_match = re.search(r'Average\s*=\s*(\d+)\s*ms', output)
        if avg_match:
            result['latency'] = f"{avg_match.group(1)}ms"
            result['rtt'] = avg_match.group(1)
        else:
            avg_match = re.search(r'rtt\s+min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/', output)
            if avg_match:
                result['latency'] = f"{avg_match.group(1)}ms"
                result['rtt'] = avg_match.group(1)

        return result

    def _parse_nslookup(self, output: str) -> Dict[str, Any]:
        """Parse nslookup output for DNS info."""
        result = {}

        # Look for Name: lines
        name_match = re.search(r'Name:\s*(\S+)', output)
        if name_match:
            hostname = name_match.group(1)
            result['hostname'] = hostname
            result['dns_name'] = hostname
            result['fqdn'] = hostname
            result['reverse_dns'] = hostname

        # Look for "name = " in PTR records
        ptr_match = re.search(r'name\s*=\s*(\S+?)\.?\s*$', output, re.MULTILINE)
        if ptr_match:
            hostname = ptr_match.group(1)
            result['hostname'] = hostname
            result['reverse_dns'] = hostname

        return result

    def _parse_portscan(self, output: str) -> Dict[str, Any]:
        """Parse port scan output."""
        result = {}

        # nmap grepable output
        ports_match = re.findall(r'(\d+)/open/tcp//([^/]*)', output)
        if ports_match:
            open_ports = [p[0] for p in ports_match]
            services = [f"{p[1]}:{p[0]}" for p in ports_match if p[1]]
            result['open_ports'] = ', '.join(open_ports)
            result['listening_services'] = ', '.join(services)
            result['ports'] = open_ports
            result['services'] = services
        else:
            # PowerShell/bash scan output (just port numbers)
            port_matches = re.findall(r'^(\d+)\s*(?:open)?', output, re.MULTILINE)
            if port_matches:
                result['open_ports'] = ', '.join(port_matches)
                result['ports'] = port_matches

        return result

    def _parse_traceroute(self, output: str) -> Dict[str, Any]:
        """Parse traceroute output."""
        result = {}

        # Count hop lines (numbered lines with ms values or *)
        hop_lines = re.findall(r'^\s*(\d+)\s+', output, re.MULTILINE)
        if hop_lines:
            hop_count = len(set(hop_lines))
            result['hop_count'] = hop_count
            result['hops'] = hop_count
            result['ttl'] = max(int(h) for h in hop_lines)

        return result

    def _parse_os_info(self, output: str) -> Dict[str, Any]:
        """Parse OS info output (WMI JSON or Linux text)."""
        result = {}
        import json

        try:
            data = json.loads(output)
            if isinstance(data, dict):
                result['os_name'] = data.get('Caption', data.get('PRETTY_NAME', ''))
                result['os_version'] = data.get('Version', data.get('VERSION_ID', ''))
                result['os_build'] = data.get('BuildNumber', '')
            return result
        except (json.JSONDecodeError, ValueError):
            pass

        # Linux os-release format
        name_match = re.search(r'PRETTY_NAME="?([^"\n]+)', output)
        if name_match:
            result['os_name'] = name_match.group(1)
            result['distro'] = name_match.group(1)

        version_match = re.search(r'VERSION_ID="?([^"\n]+)', output)
        if version_match:
            result['os_version'] = version_match.group(1)

        # uname output
        kernel_match = re.search(r'Linux\s+\S+\s+([\d.]+\S+)', output)
        if kernel_match:
            result['kernel_version'] = kernel_match.group(1)

        return result

    def _parse_network_adapters(self, output: str) -> Dict[str, Any]:
        """Parse network adapter info."""
        result = {}
        import json

        try:
            data = json.loads(output)
            if isinstance(data, list) and data:
                first = data[0]
                result['mac_address'] = first.get('MACAddress', '')
                result['adapter_name'] = first.get('Description', first.get('Name', ''))
                result['network_adapters'] = f"{len(data)} adapter(s)"
            elif isinstance(data, dict):
                result['mac_address'] = data.get('MACAddress', '')
                result['adapter_name'] = data.get('Description', '')
        except (json.JSONDecodeError, ValueError):
            # Try regex for MAC
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', output)
            if mac_match:
                result['mac_address'] = mac_match.group(0)

        return result

    def _parse_whois(self, output: str) -> Dict[str, Any]:
        """Parse whois output."""
        result = {}

        org_match = re.search(r'(?:OrgName|org-name|Organization):\s*(.+)', output, re.IGNORECASE)
        if org_match:
            result['organization'] = org_match.group(1).strip()

        country_match = re.search(r'(?:Country|country):\s*(\S+)', output)
        if country_match:
            result['country'] = country_match.group(1).strip()

        net_match = re.search(r'(?:NetRange|inetnum):\s*(.+)', output, re.IGNORECASE)
        if net_match:
            result['net_range'] = net_match.group(1).strip()

        desc_match = re.search(r'(?:descr|NetName):\s*(.+)', output, re.IGNORECASE)
        if desc_match:
            result['net_description'] = desc_match.group(1).strip()

        return result

    def _parse_generic(self, output: str, expected: List[str]) -> Dict[str, Any]:
        """Generic parser - look for key:value patterns."""
        result = {}
        for line in output.split('\n'):
            for attr in expected:
                if attr.lower().replace('_', ' ') in line.lower():
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        result[attr] = parts[1].strip()
                        break
        return result

    @staticmethod
    def _validate_target(target: str) -> bool:
        """Validate target is a safe IP or hostname."""
        target = target.strip()
        if IPV4_RE.match(target):
            return True
        if HOSTNAME_RE.match(target):
            return True
        return False

    @staticmethod
    def _resolve_docker_target(target: str) -> str:
        """In Docker, translate localhost references to the Docker host."""
        LOCALHOST_ALIASES = {'127.0.0.1', 'localhost', '::1'}
        if target.strip().lower() in LOCALHOST_ALIASES:
            return 'host.docker.internal'
        return target

    @staticmethod
    def _is_blocked(command: str) -> bool:
        """Check if command matches any blocked patterns."""
        return any(p.search(command) for p in BLOCKED_PATTERNS)
