"""L0-L4 Automation Maturity Gate.

Determines whether a response skill may be auto-executed or must be queued
for human-in-the-loop (HITL) approval, based on:

1. The *blast radius* of the skill (how much damage/disruption it can cause
   if executed incorrectly or against the wrong target).
2. The *automation tier* currently configured for the deployment/tenant
   (how much autonomy the operator has granted the system).

This is intentionally a small, dependency-free module so it can be imported
from both the orchestrator and tests without pulling in the rest of the
response stack.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional

logger = logging.getLogger("maturity-gate")


class BlastRadius(IntEnum):
    """How much potential damage/disruption a response skill can cause."""
    MINIMAL = 0   # Informational / notification only, no system state change
    LOW = 1       # Reversible, narrowly-scoped change (e.g. enable MFA on one user)
    MEDIUM = 2    # Reversible, moderate-scope change (e.g. block an IP/domain)
    HIGH = 3      # Disruptive change with user/business impact (e.g. kill a process, reset creds)
    CRITICAL = 4  # Wide-reaching or hard-to-reverse change (e.g. isolate a host from the network)


class AutomationTier(IntEnum):
    """How much autonomy the system has been granted to act without a human."""
    L0_OBSERVE = 0     # No automation: every action must be manually approved
    L1_RECOMMEND = 1   # System recommends actions; MINIMAL blast-radius actions may auto-run
    L2_SUPERVISED = 2  # LOW blast-radius actions may auto-run in addition to MINIMAL
    L3_CONDITIONAL = 3 # MEDIUM blast-radius actions may auto-run in addition to LOW/MINIMAL
    L4_FULL_AUTO = 4   # HIGH and CRITICAL blast-radius actions may also auto-run


# Maps each known response skill (normalized, hyphen-separated, lowercase) to
# its blast radius. Unknown skills fall back to DEFAULT_BLAST_RADIUS (fail-closed).
SKILL_BLAST_RADIUS: Dict[str, BlastRadius] = {
    "notify-soc-team": BlastRadius.MINIMAL,
    "enable-mfa": BlastRadius.LOW,
    "quarantine-file": BlastRadius.LOW,
    "update-firewall": BlastRadius.MEDIUM,
    "patch-system": BlastRadius.MEDIUM,
    "block-ip": BlastRadius.MEDIUM,
    "block-domain": BlastRadius.MEDIUM,
    "reset-credentials": BlastRadius.HIGH,
    "kill-process": BlastRadius.HIGH,
    "isolate-host": BlastRadius.CRITICAL,
}

# Unknown/unmapped skills are treated as the most dangerous tier so they are
# never silently auto-executed.
DEFAULT_BLAST_RADIUS = BlastRadius.CRITICAL

# The minimum automation tier required before a given blast radius may be
# auto-executed without human approval.
MIN_TIER_FOR_AUTO_EXECUTE: Dict[BlastRadius, AutomationTier] = {
    BlastRadius.MINIMAL: AutomationTier.L0_OBSERVE,
    BlastRadius.LOW: AutomationTier.L1_RECOMMEND,
    BlastRadius.MEDIUM: AutomationTier.L2_SUPERVISED,
    BlastRadius.HIGH: AutomationTier.L3_CONDITIONAL,
    BlastRadius.CRITICAL: AutomationTier.L4_FULL_AUTO,
}


@dataclass
class GateDecision:
    """Result of evaluating a skill against the current automation tier."""
    skill_name: str
    blast_radius: BlastRadius
    required_tier: AutomationTier
    current_tier: AutomationTier
    auto_execute: bool
    reason: str


def _normalize(skill_name: str) -> str:
    return skill_name.replace("_", "-").lower()


class MaturityGate:
    """Evaluates whether a response skill may auto-execute at the current tier."""

    def __init__(self, tier: Optional[AutomationTier] = None):
        if tier is None:
            tier = self._tier_from_env()
        self.tier = tier

    @staticmethod
    def _tier_from_env() -> AutomationTier:
        """Read the default automation tier from SOC_AUTOMATION_TIER env var.

        Falls back to L1_RECOMMEND (conservative: only MINIMAL actions
        auto-execute) if unset or invalid.
        """
        raw = os.getenv("SOC_AUTOMATION_TIER", "L1_RECOMMEND").strip().upper()
        for member in AutomationTier:
            if member.name == raw or member.name == f"L{raw}" or str(member.value) == raw:
                return member
        logger.warning(
            "Invalid SOC_AUTOMATION_TIER=%r, defaulting to L1_RECOMMEND", raw
        )
        return AutomationTier.L1_RECOMMEND

    def set_tier(self, tier: AutomationTier) -> None:
        self.tier = tier

    def evaluate(self, skill_name: str) -> GateDecision:
        """Decide whether `skill_name` may be auto-executed at the current tier."""
        normalized = _normalize(skill_name)
        blast_radius = SKILL_BLAST_RADIUS.get(normalized)
        unknown_skill = blast_radius is None
        if unknown_skill:
            blast_radius = DEFAULT_BLAST_RADIUS

        required_tier = MIN_TIER_FOR_AUTO_EXECUTE[blast_radius]
        auto_execute = self.tier >= required_tier

        if unknown_skill:
            reason = (
                f"Skill '{skill_name}' is not in the blast-radius registry; "
                f"treated as {blast_radius.name} (fail-closed). "
                f"Requires tier >= {required_tier.name}, current tier is {self.tier.name}."
            )
        elif auto_execute:
            reason = (
                f"Skill '{skill_name}' has blast radius {blast_radius.name}, "
                f"which is permitted to auto-execute at tier {self.tier.name} "
                f"(requires >= {required_tier.name})."
            )
        else:
            reason = (
                f"Skill '{skill_name}' has blast radius {blast_radius.name}, "
                f"which requires tier >= {required_tier.name} to auto-execute; "
                f"current tier is {self.tier.name}. Queuing for human approval."
            )

        return GateDecision(
            skill_name=skill_name,
            blast_radius=blast_radius,
            required_tier=required_tier,
            current_tier=self.tier,
            auto_execute=auto_execute,
            reason=reason,
        )


# Module-level singleton, mirroring the PromptManager pattern used elsewhere.
maturity_gate = MaturityGate()
