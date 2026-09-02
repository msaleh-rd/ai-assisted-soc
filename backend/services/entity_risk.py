"""Entity-Risk Scoring: time-decayed cumulative risk per entity with auto-promotion.

Individual alerts against an entity may each be sub-critical (e.g. risk_score 0.3-0.6),
but repeated sub-critical activity against the same entity within a short window is
itself a strong signal of compromise (e.g. a user with three separate "suspicious
login" alerts in an hour). This module tracks a decayed cumulative risk score per
entity and signals when an entity should be auto-promoted to a full investigation.

Time decay uses exponential half-life: risk contributed by older alerts fades over
time so that sparse, unrelated low-risk alerts don't falsely trigger promotion.
"""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("entity-risk")


# Maps categorical alert severity to a numeric risk contribution, matching the
# scale used by the triage severity-evaluator skill (0.0-1.0).
SEVERITY_RISK_SCORES: Dict[str, float] = {
    "critical": 0.95,
    "high": 0.80,
    "medium": 0.50,
    "low": 0.20,
    "informational": 0.05,
}


def severity_to_risk_score(severity: str) -> float:
    """Convert a categorical alert severity into a numeric risk contribution."""
    return SEVERITY_RISK_SCORES.get(str(severity).lower(), 0.20)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class EntityRiskState:
    """Current decayed risk state for a single entity."""
    entity_id: str
    entity_type: str
    cumulative_risk: float = 0.0
    last_updated: datetime = field(default_factory=_now)
    contributing_alert_ids: List[str] = field(default_factory=list)
    promoted: bool = False
    promoted_at: Optional[datetime] = None


@dataclass
class RiskUpdateResult:
    """Result of recording a new alert's risk contribution against an entity."""
    entity_id: str
    entity_type: str
    previous_risk: float
    decayed_risk_before_update: float
    added_risk: float
    cumulative_risk: float
    threshold: float
    promoted: bool
    newly_promoted: bool
    reason: str


class EntityRiskTracker:
    """Tracks time-decayed cumulative risk per entity and signals auto-promotion."""

    def __init__(
        self,
        decay_half_life_hours: Optional[float] = None,
        promotion_threshold: Optional[float] = None,
    ):
        """
        Args:
            decay_half_life_hours: Hours for accumulated risk to decay by half.
                Defaults to ENTITY_RISK_DECAY_HALF_LIFE_HOURS env var, or 12.
            promotion_threshold: Cumulative decayed risk at which an entity is
                flagged for auto-promotion to a full investigation. Defaults to
                ENTITY_RISK_PROMOTION_THRESHOLD env var, or 1.2 (e.g. reached by
                three "medium" (0.5) severity alerts in quick succession).
        """
        self.decay_half_life_hours = (
            decay_half_life_hours
            if decay_half_life_hours is not None
            else float(os.getenv("ENTITY_RISK_DECAY_HALF_LIFE_HOURS", "12"))
        )
        self.promotion_threshold = (
            promotion_threshold
            if promotion_threshold is not None
            else float(os.getenv("ENTITY_RISK_PROMOTION_THRESHOLD", "1.2"))
        )
        self._states: Dict[str, EntityRiskState] = {}

    def _decay_factor(self, elapsed_seconds: float) -> float:
        if elapsed_seconds <= 0:
            return 1.0
        half_life_seconds = self.decay_half_life_hours * 3600.0
        if half_life_seconds <= 0:
            return 0.0
        return math.pow(0.5, elapsed_seconds / half_life_seconds)

    def get_risk(self, entity_id: str) -> float:
        """Return the current decayed cumulative risk for an entity (0.0 if unseen)."""
        state = self._states.get(entity_id)
        if state is None:
            return 0.0
        elapsed = (_now() - state.last_updated).total_seconds()
        return state.cumulative_risk * self._decay_factor(elapsed)

    def record_alert(
        self,
        entity_id: str,
        entity_type: str,
        alert_id: str,
        risk_score: float,
    ) -> RiskUpdateResult:
        """Record a new alert's risk contribution against an entity.

        Applies exponential time decay to the existing cumulative risk before
        adding the new contribution, then checks whether the entity should be
        promoted to a full investigation.
        """
        now = _now()
        state = self._states.get(entity_id)
        if state is None:
            state = EntityRiskState(entity_id=entity_id, entity_type=entity_type)
            self._states[entity_id] = state

        previous_risk = state.cumulative_risk
        elapsed = (now - state.last_updated).total_seconds()
        decayed_risk_before_update = previous_risk * self._decay_factor(elapsed)

        state.cumulative_risk = decayed_risk_before_update + risk_score
        state.last_updated = now
        state.contributing_alert_ids.append(alert_id)

        newly_promoted = False
        if state.cumulative_risk >= self.promotion_threshold and not state.promoted:
            state.promoted = True
            state.promoted_at = now
            newly_promoted = True

        if newly_promoted:
            reason = (
                f"Entity '{entity_id}' cumulative risk {state.cumulative_risk:.2f} crossed "
                f"promotion threshold {self.promotion_threshold:.2f} after "
                f"{len(state.contributing_alert_ids)} contributing alerts; auto-promoting "
                f"to investigation."
            )
        elif state.promoted:
            reason = f"Entity '{entity_id}' already promoted; risk continues to accumulate."
        else:
            reason = (
                f"Entity '{entity_id}' cumulative risk {state.cumulative_risk:.2f} below "
                f"promotion threshold {self.promotion_threshold:.2f}."
            )

        logger.info(reason)

        return RiskUpdateResult(
            entity_id=entity_id,
            entity_type=entity_type,
            previous_risk=previous_risk,
            decayed_risk_before_update=decayed_risk_before_update,
            added_risk=risk_score,
            cumulative_risk=state.cumulative_risk,
            threshold=self.promotion_threshold,
            promoted=state.promoted,
            newly_promoted=newly_promoted,
            reason=reason,
        )

    def get_state(self, entity_id: str) -> Optional[EntityRiskState]:
        """Return the raw tracked state for an entity, if any."""
        return self._states.get(entity_id)

    def list_states(self) -> List[EntityRiskState]:
        """Return every currently-tracked entity's state, with decay applied to
        `cumulative_risk` as-of now (read-only snapshot; does not mutate stored
        state). Used by the read-only AI-governance API/UI surface."""
        snapshots: List[EntityRiskState] = []
        now = _now()
        for state in self._states.values():
            elapsed = (now - state.last_updated).total_seconds()
            decayed = state.cumulative_risk * self._decay_factor(elapsed)
            snapshots.append(EntityRiskState(
                entity_id=state.entity_id,
                entity_type=state.entity_type,
                cumulative_risk=decayed,
                last_updated=state.last_updated,
                contributing_alert_ids=list(state.contributing_alert_ids),
                promoted=state.promoted,
                promoted_at=state.promoted_at,
            ))
        return snapshots

    def reset(self, entity_id: str) -> None:
        """Clear tracked state for a single entity (e.g. after manual incident closure)."""
        self._states.pop(entity_id, None)

    def clear(self) -> None:
        """Clear all tracked state. Primarily for tests."""
        self._states.clear()


# Module-level singleton, mirroring the AlertDeduplicator/MaturityGate pattern
# used elsewhere in the codebase.
entity_risk_tracker = EntityRiskTracker()
