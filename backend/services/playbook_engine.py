"""Playbook Engine — Wave 3 / Phase K.

Declarative, YAML-defined incident-response playbooks: a `trigger` (severity +
tag match against an incoming alert) followed by an ordered list of `steps`
executed against the investigation's shared blackboard
(`InvestigationContext`). Each step calls into an existing, real capability
already present in this codebase -- no mocked/simulated execution:

    isolate_host    -> ResponseOrchestrator.execute_response_plan() (full
                       Maturity Gate / kill-switch / skill-authorization
                       safety stack, same path as any other response action)
    investigate     -> the same TriageAgent/EvidenceAgent/CompressionAgent/
                       RCAAnalystAgent classes the static 5-phase pipeline uses
    notify          -> ResponseSkillExecutor's real 'notify-soc-team' skill
    generate_report -> a lightweight incident summary built from the
                       investigation's own state (see docstring on
                       _run_generate_report for why the full ReportGenerator
                       isn't wired in this pass)

`on_failure` semantics per step: `abort` stops the whole playbook; `continue`
records the failure and proceeds to the next step; `retry` retries the step
once, then falls back to `continue` semantics if it fails again.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("playbook_engine")

DEFAULT_PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"
VALID_STEP_TYPES = {"isolate_host", "investigate", "notify", "generate_report"}
VALID_ON_FAILURE = {"abort", "continue", "retry"}


@dataclass
class PlaybookStep:
    """A single ordered step within a playbook."""
    id: str
    name: str
    type: str
    params: Dict[str, Any] = field(default_factory=dict)
    on_failure: str = "abort"
    timeout_seconds: Optional[int] = None


@dataclass
class Playbook:
    """A declarative, trigger-matched incident-response playbook."""
    id: str
    name: str
    version: str
    trigger: Dict[str, Any]
    steps: List[PlaybookStep]
    description: str = ""


@dataclass
class StepResult:
    """Outcome of executing a single playbook step."""
    step_id: str
    step_name: str
    status: str  # "success" | "failed" | "skipped"
    detail: Any = None
    retried: bool = False


@dataclass
class PlaybookExecutionResult:
    """Outcome of executing an entire playbook."""
    playbook_id: str
    aborted: bool
    step_results: List[StepResult] = field(default_factory=list)


class PlaybookValidationError(ValueError):
    """Raised when a loaded playbook's shape doesn't satisfy playbook.schema.json's
    required structure. (Hand-validated rather than pulling in a jsonschema
    dependency -- this codebase already hand-validates YAML-defined structures
    the same way, e.g. detection_engine.py's DetectionRule.)"""


class PlaybookLoader:
    """Loads and validates playbook YAML files from a directory."""

    @staticmethod
    def load_all(playbooks_dir: Path = DEFAULT_PLAYBOOKS_DIR) -> List[Playbook]:
        playbooks: List[Playbook] = []
        if not playbooks_dir.exists():
            return playbooks
        for yaml_path in sorted(playbooks_dir.glob("*.yaml")) + sorted(playbooks_dir.glob("*.yml")):
            try:
                playbooks.append(PlaybookLoader.load_file(yaml_path))
            except Exception as e:
                logger.warning(f"Skipping invalid playbook '{yaml_path}': {e}")
        return playbooks

    @staticmethod
    def load_file(yaml_path: Path) -> Playbook:
        with open(yaml_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return PlaybookLoader.from_dict(raw)

    @staticmethod
    def from_dict(raw: Dict[str, Any]) -> Playbook:
        for required_key in ("id", "name", "version", "trigger", "steps"):
            if required_key not in raw:
                raise PlaybookValidationError(f"Playbook missing required field '{required_key}'")

        steps = []
        for raw_step in raw["steps"]:
            for required_key in ("id", "name", "type"):
                if required_key not in raw_step:
                    raise PlaybookValidationError(f"Playbook step missing required field '{required_key}': {raw_step}")
            if raw_step["type"] not in VALID_STEP_TYPES:
                raise PlaybookValidationError(f"Unknown step type '{raw_step['type']}' (must be one of {VALID_STEP_TYPES})")
            on_failure = raw_step.get("on_failure", "abort")
            if on_failure not in VALID_ON_FAILURE:
                raise PlaybookValidationError(f"Invalid on_failure '{on_failure}' (must be one of {VALID_ON_FAILURE})")
            steps.append(PlaybookStep(
                id=raw_step["id"],
                name=raw_step["name"],
                type=raw_step["type"],
                params=raw_step.get("params", {}) or {},
                on_failure=on_failure,
                timeout_seconds=raw_step.get("timeout_seconds"),
            ))

        return Playbook(
            id=raw["id"],
            name=raw["name"],
            version=str(raw["version"]),
            trigger=raw["trigger"] or {},
            steps=steps,
            description=raw.get("description", ""),
        )


def alert_matches_trigger(alert_data: Dict[str, Any], trigger: Dict[str, Any]) -> bool:
    """True if the given alert satisfies a playbook's trigger: severity must be
    in the trigger's severity list (case-insensitive), AND at least one trigger
    tag must appear among the alert's classification/tactic/technique/tags/
    description fields (case-insensitive substring match)."""
    trigger_severities = {s.lower() for s in trigger.get("severity", [])}
    if trigger_severities:
        alert_severity = str(alert_data.get("severity_name") or alert_data.get("severity") or "").lower()
        if alert_severity not in trigger_severities:
            return False

    trigger_tags = [t.lower() for t in trigger.get("tags", [])]
    if trigger_tags:
        haystack_parts = [
            str(alert_data.get("classification", "")),
            str(alert_data.get("alert_type", "")),
            str(alert_data.get("category", "")),
            str(alert_data.get("mitre_tactic", "")),
            str(alert_data.get("mitre_technique", "")),
            str(alert_data.get("technique", "")),
            str(alert_data.get("description", "")),
            " ".join(str(t) for t in alert_data.get("tags", []) or []),
        ]
        haystack = " ".join(haystack_parts).lower()
        if not any(tag in haystack for tag in trigger_tags):
            return False

    return True


class PlaybookEngine:
    """Loads playbooks, matches incoming alerts against triggers, and executes
    their steps in order against a real InvestigationContext."""

    def __init__(self, playbooks_dir: Path = DEFAULT_PLAYBOOKS_DIR):
        self.playbooks_dir = playbooks_dir
        self._playbooks: Optional[List[Playbook]] = None

    def _load(self) -> List[Playbook]:
        if self._playbooks is None:
            self._playbooks = PlaybookLoader.load_all(self.playbooks_dir)
        return self._playbooks

    def reload(self) -> List[Playbook]:
        self._playbooks = PlaybookLoader.load_all(self.playbooks_dir)
        return self._playbooks

    def find_matching_playbook(self, alert_data: Dict[str, Any]) -> Optional[Playbook]:
        """Returns the first playbook whose trigger matches this alert, or None."""
        for playbook in self._load():
            if alert_matches_trigger(alert_data, playbook.trigger):
                return playbook
        return None

    async def execute_playbook(self, playbook: Playbook, context: Any) -> PlaybookExecutionResult:
        """Executes every step in `playbook.steps`, in exact declared order,
        against the given InvestigationContext. Honors each step's on_failure
        policy. Never raises -- a step handler exception is treated the same
        as a failed step result."""
        step_results: List[StepResult] = []
        aborted = False

        for step in playbook.steps:
            result = await self._run_step(step, context)
            if result.status == "failed" and step.on_failure == "retry":
                logger.warning(f"Playbook step '{step.id}' failed, retrying once.")
                result = await self._run_step(step, context)
                result.retried = True

            step_results.append(result)

            if result.status == "failed" and step.on_failure == "abort":
                logger.warning(f"Playbook '{playbook.id}' aborted at step '{step.id}' (on_failure=abort).")
                aborted = True
                break
            if result.status == "failed":
                logger.info(f"Playbook '{playbook.id}' step '{step.id}' failed but on_failure="
                            f"'{step.on_failure}' -- continuing.")

        return PlaybookExecutionResult(playbook_id=playbook.id, aborted=aborted, step_results=step_results)

    async def _run_step(self, step: PlaybookStep, context: Any) -> StepResult:
        try:
            handler = {
                "isolate_host": self._run_isolate_host,
                "investigate": self._run_investigate,
                "notify": self._run_notify,
                "generate_report": self._run_generate_report,
            }[step.type]
            return await handler(step, context)
        except Exception as e:
            logger.warning(f"Playbook step '{step.id}' ({step.type}) raised an exception: {e}")
            return StepResult(step_id=step.id, step_name=step.name, status="failed", detail={"error": str(e)})

    def _infer_primary_host(self, context: Any) -> str:
        for ent in getattr(context, "entities", []) or []:
            if isinstance(ent, dict) and ent.get("type") == "host" and ent.get("id"):
                return ent["id"]
        alert = getattr(context, "alert_data", {}) or {}
        return alert.get("computer_name") or alert.get("host") or "unknown-host"

    async def _run_isolate_host(self, step: PlaybookStep, context: Any) -> StepResult:
        from backend.services.response_orchestration import ResponseOrchestrator
        from backend.services.rca_engine import ResponseAction, ResponseRecommendation

        target = step.params.get("target") or self._infer_primary_host(context)
        recommendation = ResponseRecommendation(
            action=ResponseAction.ISOLATE_HOST,
            priority="critical",
            target=target,
            description=step.name,
            prerequisites=[],
            estimated_time_minutes=max(1, (step.timeout_seconds or 60) // 60),
            success_criteria=[],
            rollback_steps=[],
            business_impact="Host isolated from network pending investigation.",
        )

        @dataclass
        class _PlaybookRCAResult:
            immediate_actions: List[Any]
            long_term_remediation: List[Any]

        orchestrator = ResponseOrchestrator(approval_required=True)
        summary = await orchestrator.execute_response_plan(
            _PlaybookRCAResult(immediate_actions=[recommendation], long_term_remediation=[])
        )
        failed = summary.get("actions_failed") or []
        status = "failed" if failed else "success"
        return StepResult(step_id=step.id, step_name=step.name, status=status, detail=summary)

    async def _run_investigate(self, step: PlaybookStep, context: Any) -> StepResult:
        from backend.services.orchestrator import TriageAgent, EvidenceAgent, CompressionAgent, RCAAnalystAgent

        task_id_map = {
            "triage_agent": "task-triage",
            "evidence_agent": "task-evidence",
            "compression_agent": "task-compression",
            "rca_agent": "task-rca",
        }
        agents = [TriageAgent(), EvidenceAgent(), CompressionAgent(), RCAAnalystAgent()]
        reports: Dict[str, Any] = {}
        for agent in agents:
            report = await agent.execute({}, context)
            reports[task_id_map.get(agent.name, agent.name)] = report

        return StepResult(
            step_id=step.id, step_name=step.name, status="success",
            detail={
                "agents_run": [a.name for a in agents],
                "root_cause": (context.rca_findings or {}).get("root_cause"),
                "reports": reports,
            },
        )

    async def _run_notify(self, step: PlaybookStep, context: Any) -> StepResult:
        from backend.services.agentic_security import skill_authorization_gate
        from backend.services.response.skill_handlers import ResponseSkillExecutor

        investigation_id = getattr(context, "investigation_id", None) or (getattr(context, "alert_data", {}) or {}).get("alert_id", "unknown")
        skill_authorization_gate.authorize("notify-soc-team", phase="response", investigation_id=investigation_id)

        target = step.params.get("target", "soc-team")
        result = await ResponseSkillExecutor.execute_skill("notify-soc-team", target, step.params, {"investigation_id": investigation_id})
        status = "success" if result.get("success") else "failed"
        return StepResult(step_id=step.id, step_name=step.name, status=status, detail=result)

    async def _run_generate_report(self, step: PlaybookStep, context: Any) -> StepResult:
        """Builds a lightweight incident summary directly from the investigation's
        own blackboard state.

        Scoping note (documented, not silently skipped): `report_generation.py`'s
        `ReportGenerator` expects the algorithmic `rca_engine.RCAResult` type
        (produced by the sx-truerca causal analyzer), not the LLM-based
        `context.rca_findings` dict this pipeline actually produces -- wiring
        those together correctly needs an adapter that doesn't exist yet.
        Forcing a mismatched call would silently produce an incorrect report,
        so this step instead builds a real (not mocked) summary directly from
        the fields this pipeline does populate, and is a natural place to plug
        in a proper adapter in a follow-up pass.
        """
        rca = getattr(context, "rca_findings", {}) or {}
        summary = {
            "investigation_id": getattr(context, "investigation_id", None) or (getattr(context, "alert_data", {}) or {}).get("alert_id", "unknown"),
            "classification": getattr(context, "classification", "unknown"),
            "severity": getattr(context, "severity", "unknown"),
            "root_cause": rca.get("root_cause", "Not yet determined"),
            "confidence_score": rca.get("confidence_score", 0.0),
            "entity_count": len(getattr(context, "entities", []) or []),
        }
        return StepResult(step_id=step.id, step_name=step.name, status="success", detail=summary)


# Module-level singleton, mirroring detection_engine / entity_risk_tracker.
playbook_engine = PlaybookEngine()
