"""Tests for the discovery agent system."""

import pytest
import asyncio
import os
from unittest.mock import patch, AsyncMock

from backend.services.discovery.skill_loader import SkillLoader, Skill
from backend.services.discovery.agent import DiscoveryAgent, DiscoveryResult
from backend.services.discovery.enricher import DiscoveryEnricher


# --- Skill Loader Tests ---

class TestSkillLoader:
    """Tests for SKILL.md parsing and skill matching."""

    def test_load_all_skills(self):
        """Loads all SKILL.md files from the skills directory."""
        loader = SkillLoader()
        skills = loader.load_all()
        assert len(skills) >= 7  # We created 8 skills (1 is linux-only)
        names = [s.name for s in skills]
        assert 'ping-reachability' in names
        assert 'nslookup-dns' in names
        assert 'port-scan-basic' in names

    def test_skill_attributes(self):
        """Parsed skills have correct attributes."""
        loader = SkillLoader()
        skill = loader.get_skill('ping-reachability')
        assert skill is not None
        assert skill.name == 'ping-reachability'
        assert 'reachability' in skill.collects
        assert 'latency' in skill.collects
        assert skill.method == 'command'
        assert '{{ip}}' in skill.command_template

    def test_find_skills_for_attributes(self):
        """Finds correct skills for requested attributes."""
        loader = SkillLoader()
        
        # reachability -> ping
        skills = loader.find_skills_for_attributes(['reachability'])
        names = [s.name for s in skills]
        assert 'ping-reachability' in names

        # hostname -> nslookup
        skills = loader.find_skills_for_attributes(['hostname'])
        names = [s.name for s in skills]
        assert 'nslookup-dns' in names

        # open_ports -> port-scan
        skills = loader.find_skills_for_attributes(['open_ports'])
        names = [s.name for s in skills]
        assert 'port-scan-basic' in names

    def test_skill_render_command(self):
        """Command template renders with placeholders."""
        loader = SkillLoader()
        skill = loader.get_skill('ping-reachability')
        cmd = skill.render_command({'ip': '192.168.1.1'})
        assert '192.168.1.1' in cmd
        assert '{{ip}}' not in cmd

    def test_skill_render_fallback(self):
        """Fallback template renders correctly."""
        loader = SkillLoader()
        skill = loader.get_skill('ping-reachability')
        cmd = skill.render_command({'ip': '10.0.0.1'}, use_fallback=True)
        assert '10.0.0.1' in cmd
        assert '-c 3' in cmd  # Linux ping flag

    def test_no_skills_for_unknown_attribute(self):
        """Returns empty list for unknown attributes."""
        loader = SkillLoader()
        skills = loader.find_skills_for_attributes(['nonexistent_attribute'])
        assert skills == []

    def test_caching(self):
        """Skills are cached after first load."""
        loader = SkillLoader()
        skills1 = loader.load_all()
        skills2 = loader.load_all()
        assert skills1 is skills2  # Same object reference


# --- Discovery Agent Tests ---

class TestDiscoveryAgent:
    """Tests for the discovery agent execution engine."""

    def test_validate_target_ipv4(self):
        """Validates IPv4 addresses."""
        assert DiscoveryAgent._validate_target('192.168.1.1') is True
        assert DiscoveryAgent._validate_target('10.0.2.100') is True
        assert DiscoveryAgent._validate_target('255.255.255.255') is True
        assert DiscoveryAgent._validate_target('256.1.1.1') is True  # passes as hostname
        assert DiscoveryAgent._validate_target('') is False
        assert DiscoveryAgent._validate_target('not-an-ip') is True  # valid hostname

    def test_validate_target_hostname(self):
        """Validates hostnames."""
        assert DiscoveryAgent._validate_target('server01') is True
        assert DiscoveryAgent._validate_target('server.domain.com') is True
        assert DiscoveryAgent._validate_target('-invalid') is False
        assert DiscoveryAgent._validate_target('a' * 255) is False

    def test_blocked_commands(self):
        """Security policy blocks dangerous commands."""
        assert DiscoveryAgent._is_blocked('rm -rf /') is True
        assert DiscoveryAgent._is_blocked('format c:') is True
        assert DiscoveryAgent._is_blocked('Remove-Item C:\\ -Recurse') is True
        assert DiscoveryAgent._is_blocked('ping 192.168.1.1') is False
        assert DiscoveryAgent._is_blocked('nslookup 10.0.0.1') is False

    def test_parse_ping_windows(self):
        """Parses Windows ping output."""
        agent = DiscoveryAgent()
        output = """
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=2ms TTL=64
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 2ms, Average = 1ms
"""
        result = agent._parse_ping(output)
        assert result['reachability'] == 'icmp_ok'
        assert result['latency'] == '1ms'

    def test_parse_ping_unreachable(self):
        """Parses unreachable ping output."""
        agent = DiscoveryAgent()
        output = """
Pinging 10.0.0.99 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 10.0.0.99:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
"""
        result = agent._parse_ping(output)
        assert result['reachability'] == 'unreachable'

    def test_parse_nslookup(self):
        """Parses nslookup output."""
        agent = DiscoveryAgent()
        output = """Server:  dns.local
Address:  192.168.1.1

Name:    server01.corp.local
Address:  10.0.2.50
"""
        result = agent._parse_nslookup(output)
        assert result['hostname'] == 'server01.corp.local'

    def test_parse_portscan_powershell(self):
        """Parses PowerShell port scan output."""
        agent = DiscoveryAgent()
        output = "80\n443\n3389"
        result = agent._parse_portscan(output)
        assert '80' in result['open_ports']
        assert '443' in result['open_ports']
        assert '3389' in result['open_ports']

    def test_parse_traceroute(self):
        """Parses traceroute output."""
        agent = DiscoveryAgent()
        output = """
  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     5 ms     4 ms     5 ms  10.0.0.1
  3    12 ms    11 ms    12 ms  172.16.0.1
  4    15 ms    14 ms    15 ms  8.8.8.8
"""
        result = agent._parse_traceroute(output)
        assert result['hop_count'] == 4
        assert result['ttl'] == 4

    @pytest.mark.asyncio
    async def test_discover_with_mocked_execution(self):
        """Full discovery flow with mocked command execution."""
        agent = DiscoveryAgent()

        async def mock_run(command, timeout):
            if 'ping' in command:
                return "Reply from 10.0.2.100: bytes=32 time=5ms TTL=64\nAverage = 5ms"
            if 'nslookup' in command:
                return "Name:    compromised.host.local\nAddress:  10.0.2.100"
            return ""

        with patch.object(agent, '_run_command', side_effect=mock_run):
            result = await agent.discover(
                targets=['10.0.2.100'],
                attributes=['reachability', 'hostname'],
            )

        assert result.scan_id.startswith('scan-')
        assert len(result.hosts) == 1
        host = result.hosts[0]
        assert host.target == '10.0.2.100'
        assert host.status == 'alive'
        assert host.attributes['reachability'] == 'icmp_ok'
        assert 'compromised.host.local' in host.attributes.get('hostname', '')


# --- Discovery Enricher Tests ---

class TestDiscoveryEnricher:
    """Tests for the investigation integration layer."""

    def test_extract_targets_from_entity_graph(self):
        """Extracts IPs from entity graph."""
        entity_graph = {
            '10.0.2.100': {'entity_type': 'ip', 'risk_score': 0.9},
            'admin_user@10.0.2.50': {'entity_type': 'user', 'risk_score': 0.7},
            'process_svchost': {'entity_type': 'process', 'risk_score': 0.3},
        }
        targets = DiscoveryEnricher._extract_targets(entity_graph)
        assert '10.0.2.100' in targets
        assert '10.0.2.50' in targets
        # Non-IP entity should not produce a target
        assert 'process_svchost' not in targets

    def test_map_gaps_to_attributes(self):
        """Maps evidence gap descriptions to discovery attributes."""
        gaps = [
            "Network connectivity not verified",
            "No DNS resolution data",
            "Missing port scan information",
        ]
        mapping = DiscoveryEnricher._map_gaps_to_attributes(gaps)
        assert 'reachability' in mapping[gaps[0]]
        assert 'hostname' in mapping[gaps[1]] or 'reverse_dns' in mapping[gaps[1]]
        assert 'open_ports' in mapping[gaps[2]]

    def test_build_topology_edges(self):
        """Builds topology edges from discovery results."""
        enricher = DiscoveryEnricher()
        results = [
            DiscoveryResult(
                target='10.0.2.100',
                status='alive',
                attributes={'open_ports': '80, 443', 'ports': ['80', '443']},
            ),
            DiscoveryResult(
                target='10.0.2.50',
                status='alive',
                attributes={'open_ports': '80, 22', 'ports': ['80', '22']},
            ),
        ]
        edges = enricher.build_topology_edges(results)
        # Both share port 80 → should have an edge
        assert any(
            e['port'] == '80' and
            set([e['from'], e['to']]) == {'10.0.2.100', '10.0.2.50'}
            for e in edges
        )
