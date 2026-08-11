"""
RCA Configuration Module

Ported from sx-truerca (D:\Projects\sx-truerca\code\backend\src\rca_config.py)
for use within the ai-assisted-soc Docker container.

Provides dataclass-based configuration for the causal analysis engine.
All scoring factors and thresholds are configurable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import math


@dataclass
class CausalLagWindow:
    """Represents expected causal lag for a dependency type."""
    min: float = 0.0
    max: float = 120.0
    mean: float = 30.0
    
    @property
    def std(self) -> float:
        """Calculate standard deviation (assuming ~95% within min-max range)."""
        return (self.max - self.min) / 4.0
    
    def calculate_temporal_probability(self, time_diff: float) -> float:
        """
        Calculate probability that time_diff represents a causal relationship.
        Uses Gaussian distribution centered on the mean.
        """
        if self.std == 0:
            return 1.0 if abs(time_diff - self.mean) < 1 else 0.5
        
        z_score = (time_diff - self.mean) / self.std
        probability = math.exp(-0.5 * z_score ** 2)
        
        # Penalize negative time differences (effect before cause)
        if time_diff < 0:
            probability *= 0.3
        
        return probability


@dataclass
class CausalFactors:
    """Configuration for causal analysis scoring factors."""
    
    # Target service penalty
    target_service_penalty: float = 0.3
    
    # Topology-based factors
    direct_dependency_boost: float = 2.0
    transitive_dependency_boost: float = 1.5
    distant_dependency_factor: float = 1.0
    not_in_path_factor: float = 0.5
    
    # Temporal factors
    temporal_early_boost: float = 1.8
    temporal_moderate_boost: float = 1.3
    temporal_late_boost: float = 0.7
    temporal_threshold_seconds: float = 60.0
    
    # Criticality factors
    criticality_multiplier: float = 0.3
    
    # Confounder detection
    confounder_penalty: float = 0.6
    
    # Counterfactual reasoning
    clean_upstream_penalty: float = 0.7
    clean_upstream_threshold: float = 0.5
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CausalFactors':
        if not data:
            return cls()
        return cls(
            target_service_penalty=data.get('targetServicePenalty', 0.3),
            direct_dependency_boost=data.get('directDependencyBoost', 2.0),
            transitive_dependency_boost=data.get('transitiveDependencyBoost', 1.5),
            distant_dependency_factor=data.get('distantDependencyFactor', 1.0),
            not_in_path_factor=data.get('notInPathFactor', 0.5),
            temporal_early_boost=data.get('temporalEarlyBoost', 1.8),
            temporal_moderate_boost=data.get('temporalModerateBoost', 1.3),
            temporal_late_boost=data.get('temporalLateBoost', 0.7),
            temporal_threshold_seconds=data.get('temporalThresholdSeconds', 60.0),
            criticality_multiplier=data.get('criticalityMultiplier', 0.3),
            confounder_penalty=data.get('confounderPenalty', 0.6),
            clean_upstream_penalty=data.get('cleanUpstreamPenalty', 0.7),
            clean_upstream_threshold=data.get('cleanUpstreamThreshold', 0.5),
        )


@dataclass
class EvidenceConfig:
    """Configuration for evidence handling."""
    symptom_saturation_enabled: bool = True
    symptom_saturation_floor: float = 0.5
    deduplication_enabled: bool = True
    deduplication_time_bucket: int = 60
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EvidenceConfig':
        if not data:
            return cls()
        return cls(
            symptom_saturation_enabled=data.get('symptomSaturationEnabled', True),
            symptom_saturation_floor=data.get('symptomSaturationFloor', 0.5),
            deduplication_enabled=data.get('deduplicationEnabled', True),
            deduplication_time_bucket=data.get('deduplicationTimeBucket', 60),
        )
    
    def calculate_saturation_factor(self, anomaly_count: int) -> float:
        """Diminishing returns for many anomalies from same service."""
        if not self.symptom_saturation_enabled or anomaly_count <= 1:
            return 1.0
        saturation = 1.0 / math.log(1 + anomaly_count)
        return max(saturation, self.symptom_saturation_floor)


@dataclass
class AnomalyConfig:
    """Configuration for anomaly detection."""
    metric_sensitivity: float = 2.0
    pattern_matching_enabled: bool = True
    rare_template_enabled: bool = True
    rare_template_threshold: int = 3
    rare_template_score: float = 0.75
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnomalyConfig':
        if not data:
            return cls()
        return cls(
            metric_sensitivity=data.get('metricSensitivity', 2.0),
            pattern_matching_enabled=data.get('patternMatchingEnabled', True),
            rare_template_enabled=data.get('rareTemplateEnabled', True),
            rare_template_threshold=data.get('rareTemplateThreshold', 3),
            rare_template_score=data.get('rareTemplateScore', 0.75),
        )


@dataclass
class RCAConfig:
    """
    Complete RCA Configuration.
    
    Encapsulates all configurable parameters for the causal analysis engine.
    Can be initialized with defaults or loaded from API data.
    """
    
    causal_factors: CausalFactors = field(default_factory=CausalFactors)
    evidence_config: EvidenceConfig = field(default_factory=EvidenceConfig)
    anomaly_config: AnomalyConfig = field(default_factory=AnomalyConfig)
    
    # Causal lag windows per dependency type
    causal_lag_windows: Dict[str, CausalLagWindow] = field(default_factory=lambda: {
        'database': CausalLagWindow(min=10, max=120, mean=45),
        'network': CausalLagWindow(min=0, max=10, mean=3),
        'cache': CausalLagWindow(min=1, max=30, mean=10),
        'api': CausalLagWindow(min=1, max=60, mean=15),
        'queue': CausalLagWindow(min=5, max=300, mean=60),
        'storage': CausalLagWindow(min=10, max=180, mean=45),
        'external': CausalLagWindow(min=30, max=600, mean=120),
        'default': CausalLagWindow(min=0, max=120, mean=30)
    })
    
    config_id: Optional[str] = None
    config_name: Optional[str] = None
    config_scope: str = 'global'
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RCAConfig':
        if not data:
            return cls()
        
        lag_windows = {}
        raw_windows = data.get('causalLagWindows', {})
        for dep_type, window_data in raw_windows.items():
            if isinstance(window_data, dict):
                lag_windows[dep_type] = CausalLagWindow(
                    min=window_data.get('min', 0),
                    max=window_data.get('max', 120),
                    mean=window_data.get('mean', 30)
                )
        if 'default' not in lag_windows:
            lag_windows['default'] = CausalLagWindow(min=0, max=120, mean=30)
        
        return cls(
            causal_factors=CausalFactors.from_dict(data.get('causalFactors', {})),
            evidence_config=EvidenceConfig.from_dict(data.get('evidenceConfig', {})),
            anomaly_config=AnomalyConfig.from_dict(data.get('anomalyConfig', {})),
            causal_lag_windows=lag_windows if lag_windows else None,
            config_id=data.get('id'),
            config_name=data.get('name'),
            config_scope=data.get('scope', 'global'),
        )
    
    def get_causal_lag_window(self, dependency_type: str) -> CausalLagWindow:
        """Get the causal lag window for a dependency type."""
        return self.causal_lag_windows.get(
            dependency_type.lower(),
            self.causal_lag_windows.get('default', CausalLagWindow())
        )
