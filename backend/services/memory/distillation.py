"""Compounding Memory — Wave 3 / Phase J.

Learns from resolved investigations over time: for each alert signature
(classification + tactic + technique), tracks how often it turned out to be
a false positive vs a confirmed incident, and feeds a small, tightly-bounded
confidence adjustment back into Triage. This lets recurring, previously
confirmed-benign patterns get progressively de-prioritized (and recurring,
previously confirmed-malicious patterns get progressively trusted more)
without ever letting "memory" override the LLM/ground-truth signal -- the
adjustment is capped at +/-0.10 and only applies once enough history exists.

Scoping note (deliberate, documented): the plan describes a nightly Temporal
*scheduled* workflow and full few-shot exemplar feedback into the Prompt
Registry. This codebase has no existing Temporal scheduled-workflow pattern
(only the per-investigation `InvestigationWorkflow`), so `distill()` is
exposed as a plain callable invoked by a standalone script
(`backend/scripts/run_distillation.py`) -- matching the actual precedent set
by Phase A's `refresh_threat_intel.py` script, ready to be wired into a real
cron/Temporal Schedule whenever one exists. `get_exemplars()` is implemented
and unit-tested but not yet wired into `prompt_manager.py`'s few-shot
injection -- left for a follow-up pass to limit regression risk on the
prompt-registry lock file (`prompts.lock.json`).
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger("compounding_memory")

MIN_SAMPLES_FOR_ADJUSTMENT = 3
MAX_ADJUSTMENT = 0.10
DEFAULT_EXEMPLAR_BANK_SIZE = 5


def build_alert_signature(classification: str, tactic: str = "", technique: str = "") -> str:
    """Builds the stable alert-signature key used to group investigations for
    distillation: classification + tactic + technique. (The plan describes
    "category + source + technique"; classification/tactic/technique are the
    MITRE-aligned fields actually populated on TriageOutput -- a per-alert
    "source system" isn't tracked on InvestigationRecord in this schema, so
    this is the practical, available substitute.)"""
    parts = [p.strip().lower() for p in [classification or "", tactic or "", technique or ""] if p and p.strip()]
    return ":".join(parts) if parts else "unknown"


@dataclass
class SignaturePrior:
    """Distilled historical performance for one alert signature."""
    alert_signature: str
    total_count: int = 0
    false_positive_count: int = 0
    exemplar_investigation_ids: List[str] = field(default_factory=list)

    @property
    def false_positive_rate(self) -> float:
        if self.total_count == 0:
            return 0.0
        return self.false_positive_count / self.total_count

    @property
    def prior_confidence(self) -> float:
        """1.0 = this signature has always been a confirmed incident; 0.0 = always a false positive."""
        return max(0.0, min(1.0, 1.0 - self.false_positive_rate))


@dataclass
class DistillationReport:
    """Result of a single distillation pass."""
    signatures_processed: int
    priors: Dict[str, SignaturePrior] = field(default_factory=dict)


class CompoundingMemory:
    """Learns per-signature verdict priors from resolved investigations and
    exposes a small, bounded confidence adjustment for Triage."""

    def __init__(self):
        self._priors: Dict[str, SignaturePrior] = {}

    def record_verdict(
        self,
        investigation_id: str,
        alert_signature: str,
        verdict: str,
        risk_score: float = 0.0,
    ) -> None:
        """Best-effort persistence of a resolved investigation's final verdict
        (e.g. 'false_positive', 'confirmed_incident', 'benign') and its alert
        signature onto the investigations table. Never raises -- mirrors the
        DB-optional pattern used throughout this codebase (investigation_ledger,
        entity_risk)."""
        try:
            from backend.database.connection import SessionLocal
            from backend.database.postgres import InvestigationRecord
        except Exception:
            return
        if not SessionLocal:
            return
        db = SessionLocal()
        try:
            record = db.query(InvestigationRecord).filter_by(investigation_id=investigation_id).first()
            if record is None:
                record = InvestigationRecord(investigation_id=investigation_id)
                db.add(record)
            record.verdict = verdict
            record.alert_signature = alert_signature
            if risk_score:
                record.risk_score = risk_score
            db.commit()
        except Exception as e:
            logger.debug(f"CompoundingMemory.record_verdict persistence skipped: {e}")
            db.rollback()
        finally:
            db.close()

    def distill(self) -> DistillationReport:
        """Nightly-job entry point: recompute per-signature false-positive rate
        and exemplar bank from all resolved (verdict is not null) investigations.
        Populates the in-memory prior cache used by get_memory_verdict_adjustment()."""
        priors: Dict[str, SignaturePrior] = {}
        try:
            from backend.database.connection import SessionLocal
            from backend.database.postgres import InvestigationRecord
        except Exception as e:
            logger.warning(f"CompoundingMemory.distill: DB modules unavailable: {e}")
            self._priors = priors
            return DistillationReport(signatures_processed=0, priors=priors)

        if not SessionLocal:
            logger.info("CompoundingMemory.distill: no database configured, nothing to distill.")
            self._priors = priors
            return DistillationReport(signatures_processed=0, priors=priors)

        db = SessionLocal()
        try:
            records = (
                db.query(InvestigationRecord)
                .filter(InvestigationRecord.verdict.isnot(None))
                .filter(InvestigationRecord.alert_signature.isnot(None))
                .order_by(InvestigationRecord.risk_score.desc())
                .all()
            )
            for rec in records:
                sig = rec.alert_signature
                prior = priors.setdefault(sig, SignaturePrior(alert_signature=sig))
                prior.total_count += 1
                if rec.verdict == "false_positive":
                    prior.false_positive_count += 1
                if len(prior.exemplar_investigation_ids) < DEFAULT_EXEMPLAR_BANK_SIZE:
                    prior.exemplar_investigation_ids.append(rec.investigation_id)
        finally:
            db.close()

        self._priors = priors
        logger.info(f"CompoundingMemory.distill: processed {len(priors)} alert signature(s).")
        return DistillationReport(signatures_processed=len(priors), priors=priors)

    def get_memory_verdict_adjustment(self, alert_signature: str) -> float:
        """Bounded +/-0.10 confidence adjustment for the given alert signature,
        based on distilled historical verdict performance. Returns 0.0 for
        unknown/insufficiently-seen signatures (no effect until enough history
        accumulates) -- never overrides the LLM/ground-truth signal, only nudges
        it."""
        prior = self._priors.get(alert_signature)
        if not prior or prior.total_count < MIN_SAMPLES_FOR_ADJUSTMENT:
            return 0.0
        # prior_confidence 1.0 (always confirmed) -> +0.10; 0.0 (always FP) -> -0.10; 0.5 -> 0.0
        adjustment = (prior.prior_confidence - 0.5) * (2 * MAX_ADJUSTMENT)
        return max(-MAX_ADJUSTMENT, min(MAX_ADJUSTMENT, adjustment))

    def get_exemplars(self, alert_signature: str) -> List[str]:
        """Returns up to DEFAULT_EXEMPLAR_BANK_SIZE investigation IDs for the most
        evidenced resolved cases matching this signature -- intended for future
        few-shot prompt injection (not yet wired into prompt_manager.py, see
        module docstring)."""
        prior = self._priors.get(alert_signature)
        return list(prior.exemplar_investigation_ids) if prior else []

    def list_priors(self) -> List[SignaturePrior]:
        """Return every currently-distilled signature prior (read-only snapshot).
        Used by the read-only AI-governance API/UI surface."""
        return list(self._priors.values())

    def clear(self) -> None:
        """Clears in-memory distilled priors (test isolation helper)."""
        self._priors = {}


# Module-level singleton, mirroring entity_risk_tracker / detection_engine.
compounding_memory = CompoundingMemory()
