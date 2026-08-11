"""
Causal Analyzer - identifies root cause using topology and anomaly scores.

Ported from sx-truerca (D:\Projects\sx-truerca\code\backend\src\causal_analyzer.py)
for use within the ai-assisted-soc Docker container.

Uses configurable parameters from RCAConfig:
- target_service_penalty: Penalty for target being its own root cause
- direct_dependency_boost: Boost for direct upstream dependencies  
- transitive_dependency_boost: Boost for 2-hop dependencies
- temporal_early_boost: Boost for anomalies >threshold before target
- temporal_moderate_boost: Boost for anomalies 0-threshold before target
- temporal_late_boost: Penalty for anomalies after target
- temporal_threshold_seconds: Threshold distinguishing early from moderate
- criticality_multiplier: Per-dependent boost
"""

import networkx as nx
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timezone
from backend.services.sx_truerca.rca_config import RCAConfig


class CausalAnalyzer:
    """
    Causal analyzer using topology-based scoring.
    
    Scores potential root causes by combining:
    1. Anomaly magnitude (base score)
    2. Topology position (upstream = more likely)
    3. Temporal ordering (earlier = more likely)
    4. Service criticality (more dependents = more impactful)
    """
    
    def __init__(self, topology_graph: nx.DiGraph, config: Optional[RCAConfig] = None):
        self.graph = topology_graph
        self.config = config or RCAConfig()
    
    def _normalize_timestamp(self, ts):
        """Convert timestamp to naive UTC datetime for comparison."""
        dt = None
        
        if isinstance(ts, str):
            if ts.endswith('Z'):
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            else:
                try:
                    dt = datetime.fromisoformat(ts)
                except ValueError:
                    return None
        elif isinstance(ts, datetime):
            dt = ts
        else:
            return None
        
        # Convert to naive UTC for consistent comparison
        if dt is not None and dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        
        return dt
    
    def score_root_causes(
        self,
        target_service: str,
        anomaly_scores: Dict[str, float],
        anomalies: List[Dict]
    ) -> List[Tuple[str, float, str]]:
        """
        Score potential root causes using topology and anomaly data.
        
        Args:
            target_service: The service experiencing the issue
            anomaly_scores: Dict of service -> aggregated anomaly score
            anomalies: List of individual anomaly dicts with 'service', 'timestamp', etc.
            
        Returns:
            List of (service, score, reason) tuples sorted by score descending
        """
        
        if target_service not in self.graph:
            # Target not in graph - still analyze based on anomaly scores alone
            return self._score_without_topology(target_service, anomaly_scores, anomalies)
        
        # Get upstream services (potential root causes)
        upstream_services = self._get_upstream_services(target_service)
        
        # Include ALL services that have anomalies (not just upstream)
        anomalous_services = list(set(a.get('service') for a in anomalies if a.get('service')))
        candidate_services = list(set(upstream_services + [target_service] + anomalous_services))
        
        # Get target's earliest anomaly time
        target_anomalies = [a for a in anomalies if a.get('service') == target_service]
        target_first_anomaly = None
        if target_anomalies:
            timestamps = [self._normalize_timestamp(a.get('timestamp')) for a in target_anomalies]
            timestamps = [t for t in timestamps if t is not None]
            if timestamps:
                target_first_anomaly = min(timestamps)
        
        # Get config parameters
        cf = self.config.causal_factors
        
        # Score each candidate
        scores = []
        
        for service in candidate_services:
            if service not in anomaly_scores:
                continue
            
            base_score = anomaly_scores[service]
            
            # Factor 1: Topology position
            is_upstream = service in upstream_services
            is_target = service == target_service
            
            dependents = list(self.graph.predecessors(service)) if service in self.graph else []
            criticality = 1.0 + (len(dependents) * cf.criticality_multiplier)
            
            if is_target:
                topology_factor = cf.target_service_penalty
            elif is_upstream:
                path_length = self._shortest_path_length(service, target_service)
                if path_length == 1:
                    topology_factor = cf.direct_dependency_boost
                elif path_length == 2:
                    topology_factor = cf.transitive_dependency_boost
                else:
                    topology_factor = cf.distant_dependency_factor
            else:
                topology_factor = cf.not_in_path_factor
            
            # Factor 2: Temporal ordering
            service_anomalies = [a for a in anomalies if a.get('service') == service]
            temporal_factor = 1.0
            
            if service_anomalies and target_first_anomaly:
                service_timestamps = [self._normalize_timestamp(a.get('timestamp')) for a in service_anomalies]
                service_timestamps = [t for t in service_timestamps if t is not None]
                
                if service_timestamps:
                    service_first_anomaly = min(service_timestamps)
                    
                    if service_first_anomaly < target_first_anomaly:
                        time_diff = (target_first_anomaly - service_first_anomaly).total_seconds()
                        if time_diff > cf.temporal_threshold_seconds:
                            temporal_factor = cf.temporal_early_boost
                        else:
                            temporal_factor = cf.temporal_moderate_boost
                    else:
                        temporal_factor = cf.temporal_late_boost
            
            # Final score: multiplicative combination
            final_score = base_score * topology_factor * temporal_factor * criticality
            
            reason = self._determine_reason(service, anomalies)
            scores.append((service, final_score, reason))
        
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores
    
    def _score_without_topology(
        self,
        target_service: str,
        anomaly_scores: Dict[str, float],
        anomalies: List[Dict]
    ) -> List[Tuple[str, float, str]]:
        """Score candidates when target is not in topology graph."""
        
        scores = []
        for service, score in anomaly_scores.items():
            reason = self._determine_reason(service, anomalies)
            # Penalize target service even without topology
            if service == target_service:
                score *= 0.3
            scores.append((service, score, reason))
        
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores
    
    def _get_upstream_services(self, service: str, max_depth: int = 10) -> List[str]:
        """Get all upstream services (dependencies)."""
        upstream = set()
        visited = set()
        queue = [(service, 0)]
        
        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth >= max_depth:
                continue
            visited.add(current)
            
            dependencies = list(self.graph.successors(current))
            for dep in dependencies:
                upstream.add(dep)
                queue.append((dep, depth + 1))
        
        return list(upstream)
    
    def _shortest_path_length(self, source: str, target: str) -> int:
        """Calculate shortest path length between two nodes."""
        try:
            return nx.shortest_path_length(self.graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return 999
    
    def _determine_reason(self, service: str, anomalies: List[Dict]) -> str:
        """Determine human-readable reason for root cause suspicion."""
        service_anomalies = [a for a in anomalies if a.get('service') == service]
        
        if not service_anomalies:
            return "Unknown issue"
        
        top_anomaly = max(service_anomalies, key=lambda x: x.get('anomaly_score', 0))
        metric = top_anomaly.get('metric', '')
        
        # Log-based anomalies
        if metric.startswith('log_pattern_'):
            return top_anomaly.get('reason', 'Critical error detected in logs')
        elif metric in ('log_rare_event', 'log_rare_template'):
            return top_anomaly.get('reason', 'Unusual log event detected')
        
        # Metric-based anomalies
        observed = top_anomaly.get('observed_value', 0)
        baseline = top_anomaly.get('baseline_value', 0)
        
        metric_reasons = {
            'response_time_ms': f"Response time spike ({baseline:.0f}ms → {observed:.0f}ms)",
            'error_count': f"Error count spike ({baseline:.0f} → {observed:.0f})",
            'cpu_percent': f"CPU spike ({baseline:.0f}% → {observed:.0f}%)",
            'memory_mb': f"Memory spike ({baseline:.0f}MB → {observed:.0f}MB)",
        }
        
        if metric in metric_reasons:
            return metric_reasons[metric]
        
        # Fallback for SOC alert anomalies
        action = top_anomaly.get('action', '')
        if action:
            return f"{action.replace('_', ' ').title()} detected (risk: {top_anomaly.get('risk_score', top_anomaly.get('anomaly_score', 0)):.2f})"
        
        return f"{metric or 'Anomaly'} detected (score: {top_anomaly.get('anomaly_score', 0):.2f})"
