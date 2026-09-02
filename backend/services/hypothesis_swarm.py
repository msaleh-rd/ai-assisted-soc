"""Investigation Swarm — Wave 3 / Phase I.

The ReAct Supervisor normally tests one hypothesis at a time sequentially,
which is why complex cases (many entities, many distinct MITRE techniques)
can loop -- repeatedly gathering evidence trying to find the same answer a
different way. The Investigation Swarm breaks that loop for complex cases
only: it generates several competing root-cause hypotheses in a single LLM
call, scores each concurrently against the evidence already collected, and a
debate/ranking step picks a winner -- all without touching the existing
single-hypothesis path used for the common (simple) case.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List

from backend.services.investigation_context import InvestigationContext
from backend.services.llm_client import get_llm, HypothesisItem, SwarmHypothesesOutput
from backend.services.agentic_security import wrap_untrusted

logger = logging.getLogger("hypothesis_swarm")


@dataclass
class HypothesisAgent:
    """A single competing hypothesis under active investigation by the swarm."""
    hypothesis: str
    supporting_techniques: List[str] = field(default_factory=list)
    contradicting_signals: List[str] = field(default_factory=list)
    confidence: float = 0.0
    cost_budget_tokens: int = 1000
    evidence_overlap_score: float = 0.0
    combined_score: float = 0.0


@dataclass
class SwarmResult:
    """Outcome of running the Investigation Swarm against a complex case."""
    hypotheses: List[HypothesisAgent]
    winning_hypothesis: HypothesisAgent
    debate_notes: str


class InvestigationSwarm:
    """Generates and ranks competing root-cause hypotheses for complex cases."""

    COMPLEXITY_THRESHOLD = 3

    def should_swarm(self, context: InvestigationContext) -> bool:
        """Only fires for complex cases (>= COMPLEXITY_THRESHOLD entities or
        distinct MITRE techniques); simple cases keep the existing
        single-hypothesis loop -- no behavior change for the common case."""
        entity_count = len({
            e.get("id") for e in (context.entities or []) if isinstance(e, dict) and e.get("id")
        })
        technique_count = len(set(getattr(context, "mitre_techniques", []) or []))
        return entity_count >= self.COMPLEXITY_THRESHOLD or technique_count >= self.COMPLEXITY_THRESHOLD

    async def run_swarm(self, context: InvestigationContext) -> SwarmResult:
        """Generate 3-5 competing hypotheses, score each concurrently against
        the evidence already collected, and rank them via a debate/scoring node."""
        hypotheses = await self._generate_hypotheses(context)

        scored = await asyncio.gather(*[
            self._score_hypothesis(h, context) for h in hypotheses
        ])

        scored = sorted(scored, key=lambda h: h.combined_score, reverse=True)
        winner = scored[0]
        debate_notes = self._build_debate_notes(scored, winner)

        return SwarmResult(hypotheses=scored, winning_hypothesis=winner, debate_notes=debate_notes)

    async def _generate_hypotheses(self, context: InvestigationContext) -> List[HypothesisAgent]:
        entities_summary = ", ".join(
            f"{e.get('type', '?')}:{e.get('id', '?')}" for e in (context.entities or []) if isinstance(e, dict)
        ) or "no entities identified yet"

        prompt = (
            "You are a senior SOC investigator. Given the investigation context below, generate "
            "3 to 5 distinct, mutually exclusive competing hypotheses for what is really happening "
            "(e.g. ransomware staging, lateral movement from a compromised peer, insider threat, "
            "false positive / legitimate admin activity). For each, list supporting MITRE ATT&CK "
            "technique IDs and any contradicting signals.\n\n"
            f"{wrap_untrusted(entities_summary, label='entities')}\n"
            f"Classification: {context.classification} | Severity: {context.severity}"
        )

        try:
            llm = get_llm(role="supervisor")
            structured_llm = llm.with_structured_output(SwarmHypothesesOutput)
            result: SwarmHypothesesOutput = await structured_llm.ainvoke(prompt)
            items = result.hypotheses
        except Exception as e:
            logger.warning(f"Investigation Swarm hypothesis generation failed, using heuristic fallback: {e}")
            items = self._heuristic_fallback_hypotheses(context)

        return [
            HypothesisAgent(
                hypothesis=item.hypothesis,
                supporting_techniques=list(item.supporting_techniques or []),
                contradicting_signals=list(item.contradicting_signals or []),
                confidence=item.confidence,
            )
            for item in items
        ]

    def _heuristic_fallback_hypotheses(self, context: InvestigationContext) -> List[HypothesisItem]:
        """Deterministic fallback if the LLM is unavailable -- always produces at
        least a benign/false-positive counter-hypothesis alongside a generic
        malicious-activity hypothesis, so the swarm can still rank something."""
        return [
            HypothesisItem(
                hypothesis=f"Malicious activity consistent with '{context.classification}' classification",
                supporting_techniques=list(getattr(context, "mitre_techniques", []) or []),
                contradicting_signals=[],
                confidence=0.5,
            ),
            HypothesisItem(
                hypothesis="False positive / legitimate administrative activity",
                supporting_techniques=[],
                contradicting_signals=[e.get("id") for e in (context.entities or []) if isinstance(e, dict) and e.get("id")],
                confidence=0.3,
            ),
        ]

    async def _score_hypothesis(self, hyp: HypothesisAgent, context: InvestigationContext) -> HypothesisAgent:
        """Score a hypothesis against evidence already collected -- a deterministic,
        no-additional-LLM-call heuristic (keeps each hypothesis's "investigation"
        cheap/fast and fully unit-testable): overlap between the hypothesis's
        supporting techniques and techniques already observed in the
        investigation context, penalized by contradicting signals that are
        actually present among identified entities."""
        await asyncio.sleep(0)  # yield control -- genuinely concurrent under gather()

        observed_techniques = set(getattr(context, "mitre_techniques", []) or [])
        supporting = set(hyp.supporting_techniques or [])
        overlap = len(observed_techniques & supporting)
        total_supporting = max(len(supporting), 1)
        hyp.evidence_overlap_score = overlap / total_supporting

        entity_ids = {e.get("id") for e in (context.entities or []) if isinstance(e, dict)}
        contradictions_present = len(set(hyp.contradicting_signals or []) & entity_ids)
        contradiction_penalty = min(0.3, contradictions_present * 0.1)

        hyp.combined_score = max(
            0.0,
            (0.6 * hyp.confidence + 0.4 * hyp.evidence_overlap_score) - contradiction_penalty,
        )
        return hyp

    def _build_debate_notes(self, scored: List[HypothesisAgent], winner: HypothesisAgent) -> str:
        lines = [f"Ranked {len(scored)} competing hypotheses:"]
        for h in scored:
            marker = " -> WINNER" if h is winner else ""
            lines.append(
                f"  [{h.combined_score:.2f}] {h.hypothesis} "
                f"(llm_confidence={h.confidence:.2f}, evidence_overlap={h.evidence_overlap_score:.2f}){marker}"
            )
        return "\n".join(lines)


# Module-level singleton, mirroring model_router / detection_engine.
investigation_swarm = InvestigationSwarm()
