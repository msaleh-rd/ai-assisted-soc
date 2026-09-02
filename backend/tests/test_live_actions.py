"""Tests for the Live Actions Interface (Wave 2 / Phase H, Step 5)."""

import pytest

from backend.services.response.live_actions import (
    LiveActionRequest,
    LiveActionRegistry,
)


@pytest.fixture
def registry():
    return LiveActionRegistry()


class TestLiveActionDispatchDefaultsToDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_true_never_calls_executor(self, registry):
        called = {"count": 0}

        async def executor(request):
            called["count"] += 1
            return {"executed": True}

        registry.register("crowdstrike", "isolate-host", executor)
        request = LiveActionRequest(
            capability="isolate-host", vendor_id="crowdstrike", target="HOST-001", dry_run=True
        )

        result = await registry.dispatch(request)

        assert result.dry_run is True
        assert result.success is True
        assert called["count"] == 0
        assert "DRY RUN" in result.message

    @pytest.mark.asyncio
    async def test_no_registered_executor_falls_back_to_dry_run_even_if_requested_live(self, registry):
        request = LiveActionRequest(
            capability="isolate-host", vendor_id="unregistered-vendor", target="HOST-001", dry_run=False
        )
        result = await registry.dispatch(request)
        assert result.dry_run is True
        assert result.success is True
        assert "no live executor registered" in result.message


class TestLiveActionDispatchWithRegisteredExecutor:
    @pytest.mark.asyncio
    async def test_dry_run_false_with_registered_executor_calls_it(self, registry):
        async def executor(request):
            return {"isolated": request.target}

        registry.register("crowdstrike", "isolate-host", executor)
        request = LiveActionRequest(
            capability="isolate-host", vendor_id="crowdstrike", target="HOST-001", dry_run=False
        )

        result = await registry.dispatch(request)

        assert result.dry_run is False
        assert result.success is True
        assert result.details["isolated"] == "HOST-001"

    @pytest.mark.asyncio
    async def test_executor_exception_is_captured_as_failure(self, registry):
        async def failing_executor(request):
            raise RuntimeError("vendor API unreachable")

        registry.register("crowdstrike", "isolate-host", failing_executor)
        request = LiveActionRequest(
            capability="isolate-host", vendor_id="crowdstrike", target="HOST-001", dry_run=False
        )

        result = await registry.dispatch(request)

        assert result.success is False
        assert "vendor API unreachable" in result.message

    def test_unregister_removes_executor(self, registry):
        async def executor(request):
            return {}

        registry.register("crowdstrike", "isolate-host", executor)
        registry.unregister("crowdstrike", "isolate-host")
        assert ("crowdstrike", "isolate-host") not in registry._executors


class TestLiveActionAuthorization:
    @pytest.mark.asyncio
    async def test_dispatch_is_authorized_through_skill_authorization_gate(self, registry):
        request = LiveActionRequest(
            capability="isolate-host", vendor_id="crowdstrike", target="HOST-001", case_id="inv-1"
        )
        result = await registry.dispatch(request)
        assert result.authorized is True
