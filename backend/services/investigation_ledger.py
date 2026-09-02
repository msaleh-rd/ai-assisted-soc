"""Investigation Ledger — Wave 1 / Phase C.

A persistent, replayable, tamper-evident record of every agentic decision
(LLM call + structured decision) made during an investigation.

Every ReAct supervisor decision and every phase-agent LLM call (triage, RCA,
response synthesis, compression semantic summarization) writes a `LedgerEntry`
capturing exactly what prompt was sent, what the model returned, which
model/tokens/latency were involved, and what decision/evidence resulted. This
allows a full investigation to be replayed and audited after the fact, and
gives a cost/latency breakdown per investigation.

Entries are always kept in an in-memory store (fast, always available even
without a configured Postgres instance) and are additionally best-effort
persisted to Postgres (`investigation_ledger_entries`) when a database is
configured -- mirroring the DB-optional pattern used throughout this codebase
(e.g. `evidence_collection.py`, `evidence/skill_handlers.py`).
"""

import hashlib
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("investigation_ledger")


def estimate_tokens(text: str) -> int:
    """Rough token count estimate (~4 chars/token) used when exact usage metadata
    is unavailable from the LLM client (structured-output calls return the parsed
    Pydantic object directly, not a raw AIMessage with usage_metadata)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


@dataclass
class LedgerEntry:
    """A single recorded agentic decision step."""
    investigation_id: str
    step_index: int
    agent_name: str
    phase: str
    prompt_sent: str = ""
    llm_response: str = ""
    model_used: str = ""
    decision: Dict[str, Any] = field(default_factory=dict)
    evidence_cited: List[str] = field(default_factory=list)
    skills_invoked: List[str] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    prompt_hash: str = ""

    def __post_init__(self):
        if not self.prompt_hash:
            self.prompt_hash = hashlib.sha256((self.prompt_sent or "").encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InvestigationLedger:
    """Records and replays the full decision history of an investigation."""

    def __init__(self):
        self._store: Dict[str, List[LedgerEntry]] = {}

    def record(
        self,
        investigation_id: str,
        agent_name: str,
        phase: str,
        prompt_sent: str = "",
        llm_response: str = "",
        model_used: str = "",
        decision: Optional[Dict[str, Any]] = None,
        evidence_cited: Optional[List[str]] = None,
        skills_invoked: Optional[List[str]] = None,
        tokens_in: Optional[int] = None,
        tokens_out: Optional[int] = None,
        latency_ms: int = 0,
    ) -> LedgerEntry:
        """Record a new ledger entry for an investigation and return it."""
        investigation_id = investigation_id or "unknown"
        entries = self._store.setdefault(investigation_id, [])
        entry = LedgerEntry(
            investigation_id=investigation_id,
            step_index=len(entries),
            agent_name=agent_name,
            phase=phase,
            prompt_sent=prompt_sent or "",
            llm_response=llm_response or "",
            model_used=model_used or "",
            decision=decision or {},
            evidence_cited=evidence_cited or [],
            skills_invoked=skills_invoked or [],
            tokens_in=tokens_in if tokens_in is not None else estimate_tokens(prompt_sent),
            tokens_out=tokens_out if tokens_out is not None else estimate_tokens(llm_response),
            latency_ms=latency_ms or 0,
        )
        entries.append(entry)
        self._persist(entry)
        return entry

    def _persist(self, entry: LedgerEntry) -> None:
        """Best-effort persistence to Postgres. Never raises."""
        try:
            from backend.database.connection import SessionLocal
            from backend.database.postgres import InvestigationLedgerRecord
        except Exception:
            return
        if not SessionLocal:
            return
        db = SessionLocal()
        try:
            record = InvestigationLedgerRecord(
                investigation_id=entry.investigation_id,
                step_index=entry.step_index,
                timestamp=datetime.utcnow(),
                agent_name=entry.agent_name,
                phase=entry.phase,
                prompt_sent=entry.prompt_sent,
                prompt_hash=entry.prompt_hash,
                llm_response=entry.llm_response,
                model_used=entry.model_used,
                decision=entry.decision,
                evidence_cited=entry.evidence_cited,
                skills_invoked=entry.skills_invoked,
                tokens_in=entry.tokens_in,
                tokens_out=entry.tokens_out,
                latency_ms=entry.latency_ms,
            )
            db.add(record)
            db.commit()
        except Exception as e:
            logger.debug(f"Investigation ledger persistence skipped: {e}")
            db.rollback()
        finally:
            db.close()

    def replay(self, investigation_id: str) -> List[LedgerEntry]:
        """Return the ordered list of ledger entries for an investigation.

        Falls back to Postgres if nothing is present in the in-memory store
        (e.g. after a process restart).
        """
        entries = self._store.get(investigation_id)
        if entries:
            return list(entries)
        return self._replay_from_db(investigation_id)

    def _replay_from_db(self, investigation_id: str) -> List[LedgerEntry]:
        try:
            from backend.database.connection import SessionLocal
            from backend.database.postgres import InvestigationLedgerRecord
        except Exception:
            return []
        if not SessionLocal:
            return []
        db = SessionLocal()
        try:
            rows = (
                db.query(InvestigationLedgerRecord)
                .filter(InvestigationLedgerRecord.investigation_id == investigation_id)
                .order_by(InvestigationLedgerRecord.step_index.asc())
                .all()
            )
            return [
                LedgerEntry(
                    investigation_id=r.investigation_id,
                    step_index=r.step_index,
                    agent_name=r.agent_name,
                    phase=r.phase,
                    prompt_sent=r.prompt_sent or "",
                    llm_response=r.llm_response or "",
                    model_used=r.model_used or "",
                    decision=r.decision or {},
                    evidence_cited=r.evidence_cited or [],
                    skills_invoked=r.skills_invoked or [],
                    tokens_in=r.tokens_in or 0,
                    tokens_out=r.tokens_out or 0,
                    latency_ms=r.latency_ms or 0,
                    timestamp=(r.timestamp.isoformat() + "Z") if r.timestamp else (datetime.utcnow().isoformat() + "Z"),
                    prompt_hash=r.prompt_hash or "",
                )
                for r in rows
            ]
        except Exception as e:
            logger.debug(f"Investigation ledger DB replay failed: {e}")
            return []
        finally:
            db.close()

    def get_cost_summary(self, investigation_id: str) -> Dict[str, Any]:
        """Aggregate token/latency/cost metrics across an investigation's ledger."""
        entries = self.replay(investigation_id)
        total_tokens_in = sum(e.tokens_in for e in entries)
        total_tokens_out = sum(e.tokens_out for e in entries)
        total_latency_ms = sum(e.latency_ms for e in entries)
        by_agent: Dict[str, Dict[str, Any]] = {}
        for e in entries:
            bucket = by_agent.setdefault(
                e.agent_name, {"calls": 0, "tokens_in": 0, "tokens_out": 0, "latency_ms": 0}
            )
            bucket["calls"] += 1
            bucket["tokens_in"] += e.tokens_in
            bucket["tokens_out"] += e.tokens_out
            bucket["latency_ms"] += e.latency_ms
        return {
            "investigation_id": investigation_id,
            "total_steps": len(entries),
            "total_tokens_in": total_tokens_in,
            "total_tokens_out": total_tokens_out,
            "total_tokens": total_tokens_in + total_tokens_out,
            "total_latency_ms": total_latency_ms,
            "by_agent": by_agent,
        }

    def clear(self, investigation_id: str) -> None:
        """Remove in-memory entries for an investigation (does not delete DB rows)."""
        self._store.pop(investigation_id, None)


# Module-level singleton, mirroring local_threat_intel_db / yara_scanner / entity_risk_tracker
investigation_ledger = InvestigationLedger()


def record_ledger_entry(
    investigation_id: str,
    agent_name: str,
    phase: str,
    **kwargs: Any,
) -> LedgerEntry:
    """Convenience module-level helper wrapping the singleton ledger's record().

    Reused across all LLM call sites (supervisor, triage, RCA, response,
    compression) to avoid duplicated boilerplate.
    """
    return investigation_ledger.record(investigation_id, agent_name, phase, **kwargs)
