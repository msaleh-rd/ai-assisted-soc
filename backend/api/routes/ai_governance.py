"""AI Governance API — read-only visibility surface for the Wave 1-3 AI
reasoning/safety subsystems that were previously backend-only (Detection-as-Code
rules, Entity-Risk scoring, the L0-L4 Automation Maturity Gate, the Playbook
Engine, Compounding Memory priors, and the Self-Play Purple Team).

These endpoints exist purely to make already-implemented, already-tested
backend capabilities *observable and operable* from the UI, per this project's
own guiding principle: "every AI decision must be auditable and replayable."
All endpoints are read-only except `/purple-team/run`, which only replays
canned synthetic events against the real `DetectionEngine` (no production
alert data touched) and is the same safe operation already covered by
`backend/tests/test_purple_team.py`.
"""

import logging
from dataclasses import asdict
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/ai-governance", tags=["AI Governance - Wave 1-3 Capabilities"])

logger = logging.getLogger("ai-governance-api")


# -----------------------------------------------------------------------
# Detection-as-Code (Wave 2 / Phase H)
# -----------------------------------------------------------------------

@router.get("/detections")
async def list_detection_rules():
    """List every loaded Detection-as-Code rule (including auto-filed drafts)."""
    from backend.services.detection_engine import detection_engine

    rules = [
        {
            "id": r.id,
            "name": r.name,
            "severity": r.severity,
            "category": r.category,
            "tags": r.tags,
            "log_source": r.log_source,
            "condition_mode": r.condition_mode,
            "condition_count": len(r.conditions),
            "enabled": r.enabled,
            "false_positives": r.false_positives,
        }
        for r in detection_engine.rules
    ]
    return {
        "total": len(rules),
        "enabled_count": sum(1 for r in rules if r["enabled"]),
        "draft_count": sum(1 for r in rules if r["category"] == "self-play-draft"),
        "rules": rules,
    }


# -----------------------------------------------------------------------
# Entity-Risk Scoring (Quick Win 3 / Phase G)
# -----------------------------------------------------------------------

@router.get("/entity-risk")
async def list_entity_risk():
    """List every currently-tracked entity and its time-decayed cumulative risk."""
    from backend.services.entity_risk import entity_risk_tracker

    states = entity_risk_tracker.list_states()
    states.sort(key=lambda s: s.cumulative_risk, reverse=True)
    return {
        "total_tracked": len(states),
        "promoted_count": sum(1 for s in states if s.promoted),
        "promotion_threshold": entity_risk_tracker.promotion_threshold,
        "decay_half_life_hours": entity_risk_tracker.decay_half_life_hours,
        "entities": [
            {
                "entity_id": s.entity_id,
                "entity_type": s.entity_type,
                "cumulative_risk": round(s.cumulative_risk, 4),
                "last_updated": s.last_updated.isoformat(),
                "contributing_alert_count": len(s.contributing_alert_ids),
                "promoted": s.promoted,
                "promoted_at": s.promoted_at.isoformat() if s.promoted_at else None,
            }
            for s in states
        ],
    }


# -----------------------------------------------------------------------
# L0-L4 Automation Maturity Gate (Quick Win 2 / Phase F)
# -----------------------------------------------------------------------

@router.get("/maturity-gate")
async def get_maturity_gate_status():
    """Current automation tier plus the full skill blast-radius mapping and
    auto-execute verdict for every known response skill."""
    from backend.services.response.maturity_gate import (
        MaturityGate, SKILL_BLAST_RADIUS,
    )

    gate = MaturityGate()
    skills = []
    for skill_name in sorted(SKILL_BLAST_RADIUS.keys()):
        decision = gate.evaluate(skill_name)
        skills.append({
            "skill_name": skill_name,
            "blast_radius": decision.blast_radius.name,
            "required_tier": decision.required_tier.name,
            "auto_execute": decision.auto_execute,
        })
    return {
        "current_tier": gate.tier.name,
        "current_tier_value": int(gate.tier),
        "skills": skills,
    }


# -----------------------------------------------------------------------
# Playbook Engine (Wave 3 / Phase K)
# -----------------------------------------------------------------------

@router.get("/playbooks")
async def list_playbooks():
    """List every declarative YAML playbook loaded by the Playbook Engine."""
    from backend.services.playbook_engine import playbook_engine

    playbooks = playbook_engine.reload()
    return {
        "total": len(playbooks),
        "playbooks": [
            {
                "id": p.id,
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "trigger": p.trigger,
                "steps": [
                    {"id": s.id, "name": s.name, "type": s.type, "on_failure": s.on_failure}
                    for s in p.steps
                ],
            }
            for p in playbooks
        ],
    }


# -----------------------------------------------------------------------
# Compounding Memory (Wave 3 / Phase J)
# -----------------------------------------------------------------------

@router.get("/memory/priors")
async def list_memory_priors():
    """List every distilled per-alert-signature prior (false-positive rate,
    prior confidence, bounded Triage confidence adjustment)."""
    from backend.services.memory.distillation import (
        compounding_memory, MIN_SAMPLES_FOR_ADJUSTMENT,
    )

    priors = compounding_memory.list_priors()
    return {
        "total": len(priors),
        "min_samples_for_adjustment": MIN_SAMPLES_FOR_ADJUSTMENT,
        "priors": [
            {
                "alert_signature": p.alert_signature,
                "total_count": p.total_count,
                "false_positive_count": p.false_positive_count,
                "false_positive_rate": round(p.false_positive_rate, 4),
                "prior_confidence": round(p.prior_confidence, 4),
                "confidence_adjustment": round(
                    compounding_memory.get_memory_verdict_adjustment(p.alert_signature), 4
                ),
                "exemplar_investigation_ids": p.exemplar_investigation_ids,
            }
            for p in priors
        ],
    }


@router.post("/memory/distill")
async def run_distillation():
    """Trigger an on-demand distillation pass (normally run via
    `backend/scripts/run_distillation.py`)."""
    from backend.services.memory.distillation import compounding_memory

    report = compounding_memory.distill()
    return {"signatures_processed": report.signatures_processed}


# -----------------------------------------------------------------------
# Self-Play Purple Team (Wave 3 / Phase L)
# -----------------------------------------------------------------------

@router.get("/purple-team/campaigns")
async def list_purple_team_campaigns():
    """List the canned attack campaigns available to replay."""
    from backend.services.self_play.purple_team import CANNED_CAMPAIGNS

    return {
        "campaigns": [
            {
                "name": name,
                "technique_count": len(steps),
                "techniques": [f"{s.technique_id} ({s.technique_name})" for s in steps],
            }
            for name, steps in CANNED_CAMPAIGNS.items()
        ]
    }


class PurpleTeamRunRequest(BaseModel):
    campaign_name: str


@router.post("/purple-team/run")
async def run_purple_team_campaign(request: PurpleTeamRunRequest):
    """Replay a canned campaign against the real DetectionEngine and return a
    coverage report. Any uncovered technique auto-files a disabled draft rule
    under backend/detections/drafts/ for human review."""
    from backend.services.self_play.purple_team import SelfPlayCampaign

    try:
        result = SelfPlayCampaign().run_campaign(request.campaign_name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {
        "campaign_name": result.campaign_name,
        "coverage_percentage": round(result.coverage_percentage, 2),
        "draft_rules_filed": result.draft_rules_filed,
        "technique_results": [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "detected": t.detected,
                "matched_rule_ids": t.matched_rule_ids,
                "detection_latency_ms": round(t.detection_latency_ms, 3),
            }
            for t in result.technique_results
        ],
    }


# -----------------------------------------------------------------------
# Aggregate overview (single-call dashboard widget)
# -----------------------------------------------------------------------

@router.get("/overview")
async def get_ai_governance_overview():
    """Single-call summary across every Wave 1-3 AI-governance subsystem, for
    a compact UI dashboard widget."""
    from backend.services.detection_engine import detection_engine
    from backend.services.entity_risk import entity_risk_tracker
    from backend.services.playbook_engine import playbook_engine
    from backend.services.memory.distillation import compounding_memory
    from backend.services.response.maturity_gate import MaturityGate

    states = entity_risk_tracker.list_states()
    playbooks = playbook_engine.reload()
    priors = compounding_memory.list_priors()
    gate = MaturityGate()

    return {
        "detection_rules_total": len(detection_engine.rules),
        "detection_rules_enabled": sum(1 for r in detection_engine.rules if r.enabled),
        "entities_tracked": len(states),
        "entities_promoted": sum(1 for s in states if s.promoted),
        "playbooks_loaded": len(playbooks),
        "memory_signatures_learned": len(priors),
        "automation_tier": gate.tier.name,
    }
