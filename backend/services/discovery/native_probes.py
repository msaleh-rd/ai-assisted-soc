"""Python-native discovery probes — no external tool dependencies.

Used as fallback when system tools (ping, nslookup, nmap) aren't available,
which is typical inside slim Docker containers.
"""

import asyncio
import socket
import struct
import time
from typing import Dict, Any, List, Optional, Tuple


async def probe_reachability(target: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Check host reachability via TCP connect to common ports."""
    result: Dict[str, Any] = {}
    probe_ports = [80, 443, 22, 8080, 3389, 445]

    start = time.monotonic()
    reachable = False

    for port in probe_ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=min(timeout / len(probe_ports), 2.0),
            )
            writer.close()
            await writer.wait_closed()
            elapsed = (time.monotonic() - start) * 1000
            reachable = True
            result['reachability'] = 'tcp_ok'
            result['latency'] = f"{elapsed:.0f}ms"
            result['rtt'] = f"{elapsed:.0f}"
            break
        except (ConnectionRefusedError, OSError):
            # Port closed but host is alive (got RST)
            elapsed = (time.monotonic() - start) * 1000
            reachable = True
            result['reachability'] = 'tcp_rst'
            result['latency'] = f"{elapsed:.0f}ms"
            result['rtt'] = f"{elapsed:.0f}"
            break
        except (asyncio.TimeoutError, Exception):
            continue

    if not reachable:
        result['reachability'] = 'unreachable'

    return result


async def probe_dns(target: str) -> Dict[str, Any]:
    """Reverse DNS lookup using Python's socket module."""
    result: Dict[str, Any] = {}

    loop = asyncio.get_event_loop()
    try:
        # Reverse lookup
        hostname, _, _ = await loop.run_in_executor(
            None, socket.gethostbyaddr, target
        )
        result['hostname'] = hostname
        result['dns_name'] = hostname
        result['reverse_dns'] = hostname
        result['fqdn'] = hostname
    except (socket.herror, socket.gaierror, OSError):
        # Try forward lookup if target looks like a hostname
        try:
            infos = await loop.run_in_executor(
                None, socket.getaddrinfo, target, None
            )
            if infos:
                ip = infos[0][4][0]
                result['hostname'] = target
                result['resolved_ip'] = ip
        except (socket.gaierror, OSError):
            pass

    return result


async def probe_ports(
    target: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
) -> Dict[str, Any]:
    """TCP port scan using asyncio connections."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443]

    result: Dict[str, Any] = {}
    open_ports: List[str] = []

    # Scan ports concurrently with semaphore to limit concurrency
    sem = asyncio.Semaphore(20)

    async def check_port(port: int) -> Optional[int]:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout,
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                return None

    tasks = [check_port(p) for p in ports]
    results = await asyncio.gather(*tasks)

    open_ports = [str(p) for p in results if p is not None]

    if open_ports:
        result['open_ports'] = ', '.join(open_ports)
        result['ports'] = open_ports

        # Map well-known ports to service names
        port_services = {
            '21': 'ftp', '22': 'ssh', '23': 'telnet', '25': 'smtp',
            '53': 'dns', '80': 'http', '110': 'pop3', '111': 'rpc',
            '135': 'msrpc', '139': 'netbios', '143': 'imap', '443': 'https',
            '445': 'smb', '993': 'imaps', '995': 'pop3s', '3306': 'mysql',
            '3389': 'rdp', '5900': 'vnc', '8080': 'http-alt', '8443': 'https-alt',
        }
        services = [f"{port_services.get(p, 'unknown')}:{p}" for p in open_ports]
        result['listening_services'] = ', '.join(services)
        result['services'] = services
    else:
        result['open_ports'] = 'none'
        result['ports'] = []

    return result


async def run_native_discovery(
    target: str,
    attributes: List[str],
    timeout: float = 10.0,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Run Python-native discovery for requested attributes.

    Returns (attributes_dict, provenance_dict).
    """
    attrs: Dict[str, Any] = {}
    provenance: Dict[str, str] = {}

    # Which probes to run
    need_reach = any(a in attributes for a in ('reachability', 'latency', 'rtt'))
    need_dns = any(a in attributes for a in ('hostname', 'dns_name', 'fqdn', 'reverse_dns'))
    need_ports = any(a in attributes for a in ('open_ports', 'ports', 'listening_services', 'services'))

    tasks = {}
    if need_reach:
        tasks['reach'] = probe_reachability(target, timeout)
    if need_dns:
        tasks['dns'] = probe_dns(target)
    if need_ports:
        tasks['ports'] = probe_ports(target, timeout=min(timeout / 2, 2.0))

    # Run probes concurrently
    results = {}
    for key, coro in tasks.items():
        try:
            results[key] = await asyncio.wait_for(coro, timeout=timeout)
        except (asyncio.TimeoutError, Exception):
            results[key] = {}

    # Merge results
    for key, data in results.items():
        source = f"python_{key}"
        for attr, value in data.items():
            if attr in attributes:
                attrs[attr] = value
                provenance[attr] = source

    return attrs, provenance
