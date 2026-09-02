"""Live Actions Interface — Wave 2 / Phase H, Step 5.

A vendor-agnostic dispatch layer for real (eventually) response-action
execution, sitting between the Response phase's structured recommendations
and actual EDR/firewall/IAM vendor APIs. Every dispatch is authorized through
the same `SkillAuthorizationGate` (Phase E, Step 3) used by all other skill
invocation, and defaults to `dry_run=True` everywhere until Wave 4's real
vendor connectors exist -- so this interface is safe to wire in immediately
without any risk of a live, un-vetted action reaching a real system.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

logger = logging.getLogger("live_actions")


@dataclass
class LiveActionRequest:
    """A request to perform a response capability against a specific vendor."""
    capability: str
    vendor_id: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    case_id: str = "unknown"
    dry_run: bool = True


@dataclass
class LiveActionResult:
    """The outcome of dispatching a LiveActionRequest."""
    success: bool
    dry_run: bool
    authorized: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


LiveActionExecutor = Callable[[LiveActionRequest], Awaitable[Dict[str, Any]]]


class LiveActionRegistry:
    """Registers and dispatches vendor-specific executors for response capabilities."""

    def __init__(self):
        self._executors: Dict[Tuple[str, str], LiveActionExecutor] = {}

    def register(self, vendor_id: str, capability: str, executor: LiveActionExecutor) -> None:
        """Register a real executor for a (vendor_id, capability) pair.

        Until a real connector is registered (Wave 4), dispatch() for that
        pair always falls back to a dry-run simulation.
        """
        self._executors[(vendor_id, capability)] = executor

    def unregister(self, vendor_id: str, capability: str) -> None:
        self._executors.pop((vendor_id, capability), None)

    async def dispatch(self, request: LiveActionRequest) -> LiveActionResult:
        """Authorize, then execute (or dry-run simulate) a live action request."""
        from backend.services.agentic_security import skill_authorization_gate

        auth = skill_authorization_gate.authorize(
            request.capability, phase="response", investigation_id=request.case_id
        )
        if not auth.authorized:
            return LiveActionResult(
                success=False,
                dry_run=request.dry_run,
                authorized=False,
                message=f"Not authorized: {auth.reason}",
            )

        executor = self._executors.get((request.vendor_id, request.capability))

        if request.dry_run or executor is None:
            note = "" if executor is not None else " (no live executor registered for this vendor/capability yet)"
            return LiveActionResult(
                success=True,
                dry_run=True,
                authorized=True,
                message=(
                    f"[DRY RUN] Would execute '{request.capability}' via vendor "
                    f"'{request.vendor_id}' on target '{request.target}'.{note}"
                ),
                details={"params": request.params, "reason": auth.reason},
            )

        try:
            result = await executor(request)
            return LiveActionResult(
                success=True,
                dry_run=False,
                authorized=True,
                message=f"Executed '{request.capability}' via vendor '{request.vendor_id}'.",
                details=result if isinstance(result, dict) else {"result": result},
            )
        except Exception as e:
            logger.error(f"Live action execution failed for {request.vendor_id}/{request.capability}: {e}")
            return LiveActionResult(
                success=False,
                dry_run=False,
                authorized=True,
                message=f"Execution failed: {e}",
            )


# Module-level singleton, mirroring skill_authorization_gate / model_router.
live_action_registry = LiveActionRegistry()
