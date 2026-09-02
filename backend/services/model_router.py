"""Multi-Model Router — Wave 1 / Phase D, Step 1.

Every decision currently goes straight to the LLM (`llm_client.py`), even when a
deterministic rule (available via Phase A's `LocalThreatIntelDB`) could answer it
for free, instantly, and reproducibly. This module implements a
deterministic -> ML -> LLM escalation ladder: cheap, reproducible ground-truth
answers are used whenever possible, and the LLM is only invoked (or overridden)
when no deterministic signal exists.

This directly targets the confirmed bug noted in the project's own implementation
plan: indicators like a known-ransomware filename or a known-bad hash previously
scored `risk_score: 0.1` because there was nothing deterministic to check them
against before asking the LLM to guess.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from backend.services.threat_intel.local_feeds import local_threat_intel_db

logger = logging.getLogger("model_router")

# Confidence floor above which a local threat-intel match is trusted enough to
# bypass/override the LLM's own judgement entirely.
DETERMINISTIC_CONFIDENCE_THRESHOLD = 0.8


@dataclass
class RoutingDecision:
    """The outcome of routing a task through the escalation ladder."""
    tier: str  # "deterministic" | "ml" | "llm"
    result: Optional[Dict[str, Any]] = None
    source: str = ""
    reasoning: str = ""


class ModelRouter:
    """Escalation-ladder router: deterministic rules first, then ML (stub), then LLM."""

    def route(self, task: str, context: Dict[str, Any]) -> RoutingDecision:
        """Route a task to the cheapest tier that can confidently answer it.

        Args:
            task: The kind of decision being routed, e.g. "triage".
            context: Task-specific context, e.g. {"alert_data": {...}}.
        """
        if task == "triage":
            deterministic = self._deterministic_triage(context)
            if deterministic is not None:
                return deterministic

        ml_result = self._ml_tier(task, context)
        if ml_result is not None:
            return ml_result

        return RoutingDecision(
            tier="llm",
            result=None,
            source="llm_client",
            reasoning="No deterministic or ML signal available; escalating to LLM.",
        )

    def _deterministic_triage(self, context: Dict[str, Any]) -> Optional[RoutingDecision]:
        """Check triage-relevant fields against LocalThreatIntelDB for a
        high-confidence deterministic verdict (e.g. known ransomware extension
        or note filename)."""
        alert_data = context.get("alert_data") or {}
        candidates = []
        for key in ("file_name", "filename", "process_name", "file_path", "description"):
            val = alert_data.get(key)
            if val:
                candidates.append(str(val))

        for candidate in candidates:
            match = local_threat_intel_db.lookup_extension(candidate)
            if match and match.matched and match.confidence >= DETERMINISTIC_CONFIDENCE_THRESHOLD:
                return self._ransomware_verdict(candidate, match, "ransomware_extension")

            note_match = local_threat_intel_db.lookup_ransomware_note(candidate)
            if note_match and note_match.matched and note_match.confidence >= DETERMINISTIC_CONFIDENCE_THRESHOLD:
                return self._ransomware_verdict(candidate, note_match, "ransomware_note")

        return None

    def _ransomware_verdict(self, candidate: str, match: Any, matched_via: str) -> RoutingDecision:
        return RoutingDecision(
            tier="deterministic",
            source=f"local_threat_intel_db:{matched_via}",
            reasoning=(
                f"Matched known {matched_via.replace('_', ' ')} pattern "
                f"'{match.value}' in '{candidate}' (source list: {match.source_list})."
            ),
            result={
                "severity": "Critical",
                "classification": "ransomware",
                "confidence": match.confidence,
                "matched_intel": {
                    "category": match.category,
                    "source_list": match.source_list,
                    "value": match.value,
                    "detail": match.detail,
                },
            },
        )

    def _ml_tier(self, task: str, context: Dict[str, Any]) -> Optional[RoutingDecision]:
        """Placeholder for a future ML-based anomaly/classification tier.

        Currently always a no-op; architected so a real model (e.g. an
        isolation-forest anomaly scorer) can be plugged in later without
        breaking callers of `route()`.
        """
        return None


# Module-level singleton, mirroring local_threat_intel_db / entity_risk_tracker / etc.
model_router = ModelRouter()
