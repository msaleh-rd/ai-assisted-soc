"""Detection-as-Code engine — Wave 2 / Phase H, Steps 1-2.

Detection rules live as YAML files under `backend/detections/<category>/`
rather than being hardcoded in Python (e.g. `correlation_engine.py`'s inline
anomaly logic). This module is the *execution* layer that loads and evaluates
those rules; the engine's Python code interprets rules rather than encoding
conditions inline, so new detections can be authored/reviewed as data.

Each rule ships with a sibling `fixtures/<rule_id>.json` file containing
`positive` (must match) and `negative` (must NOT match) sample events, used by
both the test suite and `backend/scripts/validate_detections.py` (a CI-gate
substitute, since no CI workflow tooling exists yet in this repo).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("detection_engine")

DEFAULT_DETECTIONS_DIR = Path(__file__).resolve().parents[1] / "detections"


@dataclass
class DetectionCondition:
    """A single field-based condition within a rule's detection logic."""
    field: str
    op: str
    value: Any = None

    def evaluate(self, event: Dict[str, Any]) -> bool:
        actual = event.get(self.field)
        op = self.op.lower()

        if op == "equals":
            return actual == self.value
        if op == "not_equals":
            return actual != self.value
        if op == "gte":
            return actual is not None and float(actual) >= float(self.value)
        if op == "lte":
            return actual is not None and float(actual) <= float(self.value)
        if op == "gt":
            return actual is not None and float(actual) > float(self.value)
        if op == "lt":
            return actual is not None and float(actual) < float(self.value)
        if op == "contains":
            return actual is not None and str(self.value) in str(actual)
        if op == "in_list":
            return actual in (self.value or [])
        if op == "regex":
            return actual is not None and re.search(str(self.value), str(actual)) is not None
        if op == "exists":
            return self.field in event
        logger.warning(f"Unknown detection operator '{self.op}' for field '{self.field}'")
        return False


@dataclass
class DetectionRule:
    """A single Detection-as-Code rule loaded from YAML."""
    id: str
    name: str
    severity: str
    category: str
    tags: List[str] = field(default_factory=list)
    log_source: str = ""
    condition_mode: str = "all"  # "all" | "any"
    conditions: List[DetectionCondition] = field(default_factory=list)
    false_positives: str = ""
    playbook: Optional[str] = None
    enabled: bool = True
    source_path: str = ""

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if not self.enabled or not self.conditions:
            return False
        results = [c.evaluate(event) for c in self.conditions]
        if self.condition_mode == "any":
            return any(results)
        return all(results)


@dataclass
class DetectionMatch:
    """A rule that matched a specific event."""
    rule_id: str
    name: str
    severity: str
    category: str
    tags: List[str]
    event: Dict[str, Any]


def _parse_rule(data: Dict[str, Any], source_path: str) -> DetectionRule:
    detection = data.get("detection", {}) or {}
    conditions = [
        DetectionCondition(field=c["field"], op=c["op"], value=c.get("value"))
        for c in detection.get("rules", [])
    ]
    return DetectionRule(
        id=data["id"],
        name=data.get("name", data["id"]),
        severity=data.get("severity", "medium"),
        category=data.get("category", "uncategorized"),
        tags=data.get("tags", []) or [],
        log_source=data.get("log_source", ""),
        condition_mode=detection.get("condition", "all"),
        conditions=conditions,
        false_positives=data.get("false_positives", ""),
        playbook=data.get("playbook"),
        enabled=data.get("enabled", True),
        source_path=source_path,
    )


class DetectionRuleLoader:
    """Loads DetectionRule objects from YAML files under a detections directory."""

    @staticmethod
    def load_all(rules_dir: Path = DEFAULT_DETECTIONS_DIR) -> List[DetectionRule]:
        rules: List[DetectionRule] = []
        if not rules_dir.is_dir():
            logger.warning(f"Detections directory not found at {rules_dir}")
            return rules
        for path in sorted(rules_dir.rglob("*.yaml")):
            if "fixtures" in path.parts:
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                rules.append(_parse_rule(data, str(path)))
            except Exception as e:
                logger.error(f"Failed to load detection rule {path}: {e}")
        return rules

    @staticmethod
    def load_fixtures(rule: DetectionRule) -> Dict[str, List[Dict[str, Any]]]:
        """Load the {rule_id}.json fixtures file sitting in the rule's sibling
        fixtures/ folder. Returns {"positive": [...], "negative": [...]}."""
        rule_path = Path(rule.source_path)
        fixtures_path = rule_path.parent / "fixtures" / f"{rule.id}.json"
        if not fixtures_path.is_file():
            return {"positive": [], "negative": []}
        with open(fixtures_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {"positive": data.get("positive", []), "negative": data.get("negative", [])}


class DetectionEngine:
    """Evaluates events against a set of loaded Detection-as-Code rules."""

    def __init__(self, rules: Optional[List[DetectionRule]] = None):
        self.rules = rules if rules is not None else DetectionRuleLoader.load_all()

    def match_event(self, event: Dict[str, Any]) -> List[DetectionMatch]:
        """Return every enabled rule that matches the given event."""
        matches = []
        for rule in self.rules:
            if rule.evaluate(event):
                matches.append(DetectionMatch(
                    rule_id=rule.id,
                    name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    tags=rule.tags,
                    event=event,
                ))
        return matches

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        return next((r for r in self.rules if r.id == rule_id), None)


# Module-level singleton, mirroring model_router / local_threat_intel_db.
detection_engine = DetectionEngine()
