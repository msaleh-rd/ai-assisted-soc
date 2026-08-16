"""Discovery integration - enrich investigation entities with discovered attributes."""

from typing import Dict, List, Optional, Any

from backend.services.discovery.agent import DiscoveryAgent, DiscoveryResult
from backend.services.discovery.skill_loader import SkillLoader


class DiscoveryEnricher:
    """
    Enriches investigation entities with real network discovery data.
    
    Integrates with:
    - InvestigationBuilder: adds discovered attributes to EntityNodes
    - RCA Engine: feeds discovered topology into CausalAnalyzer graph
    - Evidence gaps: fills gaps identified by RCA with real data
    """

    def __init__(self, skills_dir: Optional[str] = None):
        self._agent = DiscoveryAgent(skills_dir)
        self._loader = SkillLoader(skills_dir)

    async def enrich_entities(
        self,
        entity_graph: Dict[str, Any],
        attributes: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Enrich entity graph entities with discovery data.
        
        Extracts IPs/hostnames from entity_graph, runs discovery,
        and returns enrichment data per entity.
        """
        if attributes is None:
            attributes = ["reachability", "hostname", "open_ports"]

        # Extract discoverable targets from entity graph
        targets = self._extract_targets(entity_graph)
        if not targets:
            return {}

        # Run discovery
        result = await self._agent.discover(
            targets=list(targets.keys()),
            attributes=attributes,
        )

        # Map results back to entity IDs
        enrichments: Dict[str, Dict[str, Any]] = {}
        for host_result in result.hosts:
            entity_ids = targets.get(host_result.target, [])
            for entity_id in entity_ids:
                enrichments[entity_id] = {
                    "discovery_status": host_result.status,
                    "discovered_attributes": host_result.attributes,
                    "provenance": host_result.provenance,
                }

        return enrichments

    async def fill_evidence_gaps(
        self,
        evidence_gaps: List[str],
        entity_graph: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Fill evidence gaps identified by RCA with real discovery data.
        
        Maps evidence gap descriptions to discoverable attributes,
        then runs targeted discovery.
        """
        # Map gap descriptions to attributes
        gap_to_attributes = self._map_gaps_to_attributes(evidence_gaps)
        if not gap_to_attributes:
            return {"filled_gaps": [], "remaining_gaps": evidence_gaps}

        targets = self._extract_targets(entity_graph)
        if not targets:
            return {"filled_gaps": [], "remaining_gaps": evidence_gaps}

        # Run targeted discovery
        all_attrs = list({a for attrs in gap_to_attributes.values() for a in attrs})
        result = await self._agent.discover(
            targets=list(targets.keys()),
            attributes=all_attrs,
        )

        filled_gaps = []
        remaining_gaps = []

        for gap in evidence_gaps:
            attrs = gap_to_attributes.get(gap, [])
            if not attrs:
                remaining_gaps.append(gap)
                continue

            # Check if any target returned data for this gap's attributes
            found_data = False
            for host in result.hosts:
                for attr in attrs:
                    val = host.attributes.get(attr)
                    if val and val != "unavailable":
                        found_data = True
                        break
                if found_data:
                    break

            if found_data:
                filled_gaps.append(gap)
            else:
                remaining_gaps.append(gap)

        return {
            "filled_gaps": filled_gaps,
            "remaining_gaps": remaining_gaps,
            "discovery_results": [
                {
                    "target": h.target,
                    "status": h.status,
                    "attributes": h.attributes,
                }
                for h in result.hosts
            ],
        }

    def build_topology_edges(
        self,
        discovery_results: List[DiscoveryResult],
    ) -> List[Dict[str, str]]:
        """
        Build topology edges from discovery results for RCA graph.
        
        Returns edges suitable for adding to NetworkX DiGraph.
        """
        edges = []
        alive_hosts = [r for r in discovery_results if r.status == "alive"]

        # Hosts that share open ports likely have service relationships
        port_groups: Dict[str, List[str]] = {}
        for host in alive_hosts:
            ports = host.attributes.get("ports", host.attributes.get("open_ports", ""))
            if isinstance(ports, str):
                ports = [p.strip() for p in ports.split(",") if p.strip()]
            for port in ports:
                port_groups.setdefault(port, []).append(host.target)

        # Create "shares_service" edges for hosts on same ports
        for port, hosts in port_groups.items():
            if len(hosts) > 1:
                for i, h1 in enumerate(hosts):
                    for h2 in hosts[i + 1:]:
                        edges.append({
                            "from": h1,
                            "to": h2,
                            "relationship": "shares_service",
                            "port": port,
                        })

        return edges

    @staticmethod
    def _extract_targets(entity_graph: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IP/hostname targets from entity graph, mapped to entity IDs."""
        import re
        ip_re = re.compile(
            r'((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)'
        )
        targets: Dict[str, List[str]] = {}

        for entity_id, node in entity_graph.items():
            # Check if entity_id itself is an IP
            if ip_re.fullmatch(entity_id):
                targets.setdefault(entity_id, []).append(entity_id)
                continue

            # Check if entity_id contains an IP (e.g. "user@10.0.2.100")
            match = ip_re.search(entity_id)
            if match:
                ip = match.group(0)
                targets.setdefault(ip, []).append(entity_id)

        return targets

    @staticmethod
    def _map_gaps_to_attributes(gaps: List[str]) -> Dict[str, List[str]]:
        """Map evidence gap descriptions to discoverable attributes."""
        keyword_map = {
            "network": ["reachability", "open_ports", "hop_count"],
            "connectivity": ["reachability", "latency"],
            "reachab": ["reachability"],
            "dns": ["hostname", "reverse_dns"],
            "hostname": ["hostname", "dns_name"],
            "port": ["open_ports", "listening_services"],
            "service": ["open_ports", "listening_services"],
            "os": ["os_name", "os_version"],
            "operating system": ["os_name", "os_version"],
            "mac": ["mac_address"],
            "adapter": ["mac_address", "adapter_name"],
            "route": ["hop_count", "hops"],
            "path": ["hop_count", "hops"],
            "owner": ["organization", "country"],
            "whois": ["organization", "net_range"],
            "organization": ["organization"],
        }

        result = {}
        for gap in gaps:
            lower = gap.lower()
            attrs = []
            for keyword, mapped_attrs in keyword_map.items():
                if keyword in lower:
                    attrs.extend(mapped_attrs)
            if attrs:
                result[gap] = list(set(attrs))
        return result
