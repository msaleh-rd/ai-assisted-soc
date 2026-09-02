"""Unit and integration tests for Entity-Risk Scoring (QW-3)."""

import pytest

from backend.services.entity_risk import (
    EntityRiskTracker,
    severity_to_risk_score,
    entity_risk_tracker,
)
from backend.services.alert_intake import AlertIntakeService
from datetime import datetime, timedelta, timezone


@pytest.fixture(autouse=True)
def clear_global_tracker():
    """Ensure the module-level singleton tracker doesn't leak state between tests."""
    entity_risk_tracker.clear()
    yield
    entity_risk_tracker.clear()


def test_severity_to_risk_score_mapping():
    assert severity_to_risk_score("critical") == 0.95
    assert severity_to_risk_score("high") == 0.80
    assert severity_to_risk_score("medium") == 0.50
    assert severity_to_risk_score("low") == 0.20
    assert severity_to_risk_score("informational") == 0.05
    # Unknown severities fail safe to a conservative "low" contribution.
    assert severity_to_risk_score("bogus") == 0.20


class TestEntityRiskTracker:
    """Unit tests for the standalone time-decayed risk tracker."""

    def test_single_sub_critical_alert_does_not_promote(self):
        tracker = EntityRiskTracker(decay_half_life_hours=12, promotion_threshold=1.2)
        result = tracker.record_alert("host:web-01", "host", "alert-1", risk_score=0.5)

        assert result.cumulative_risk == pytest.approx(0.5)
        assert result.promoted is False
        assert result.newly_promoted is False

    def test_repeated_sub_critical_alerts_accumulate_and_promote(self):
        tracker = EntityRiskTracker(decay_half_life_hours=12, promotion_threshold=1.2)

        r1 = tracker.record_alert("host:web-01", "host", "alert-1", risk_score=0.5)
        r2 = tracker.record_alert("host:web-01", "host", "alert-2", risk_score=0.5)
        r3 = tracker.record_alert("host:web-01", "host", "alert-3", risk_score=0.5)

        assert r1.promoted is False
        assert r2.promoted is False
        assert r3.cumulative_risk == pytest.approx(1.5)
        assert r3.promoted is True
        assert r3.newly_promoted is True

        # A subsequent alert against an already-promoted entity should not
        # re-trigger "newly_promoted".
        r4 = tracker.record_alert("host:web-01", "host", "alert-4", risk_score=0.1)
        assert r4.promoted is True
        assert r4.newly_promoted is False

    def test_unrelated_entities_are_tracked_independently(self):
        tracker = EntityRiskTracker(decay_half_life_hours=12, promotion_threshold=1.2)

        tracker.record_alert("host:web-01", "host", "alert-1", risk_score=0.9)
        result = tracker.record_alert("host:web-02", "host", "alert-2", risk_score=0.9)

        assert result.cumulative_risk == pytest.approx(0.9)
        assert result.promoted is False

    def test_time_decay_reduces_cumulative_risk(self):
        tracker = EntityRiskTracker(decay_half_life_hours=1, promotion_threshold=1.2)
        tracker.record_alert("host:web-01", "host", "alert-1", risk_score=1.0)

        # Simulate one full half-life (1 hour) having passed.
        state = tracker.get_state("host:web-01")
        state.last_updated = state.last_updated - timedelta(hours=1)

        decayed = tracker.get_risk("host:web-01")
        assert decayed == pytest.approx(0.5, rel=0.05)

        # Recording a new alert after decay should add on top of the decayed value.
        result = tracker.record_alert("host:web-01", "host", "alert-2", risk_score=0.5)
        assert result.decayed_risk_before_update == pytest.approx(0.5, rel=0.05)
        assert result.cumulative_risk == pytest.approx(1.0, rel=0.05)

    def test_get_risk_for_unseen_entity_is_zero(self):
        tracker = EntityRiskTracker()
        assert tracker.get_risk("host:never-seen") == 0.0

    def test_reset_clears_single_entity(self):
        tracker = EntityRiskTracker(promotion_threshold=1.2)
        tracker.record_alert("host:web-01", "host", "alert-1", risk_score=0.9)
        tracker.reset("host:web-01")
        assert tracker.get_risk("host:web-01") == 0.0


class TestAlertIntakeEntityRiskIntegration:
    """Integration tests: entity risk surfaces through the alert intake pipeline."""

    @pytest.mark.asyncio
    async def test_repeated_medium_alerts_against_same_host_promote(self):
        service = AlertIntakeService()

        base_alert = {
            'timestamp': int(datetime.utcnow().timestamp() * 1000),
            'severity': 3,  # maps to MEDIUM
            'event_type': 'process_execution',
            'user_id': 'user-a',
            'computer_name': 'SHARED-HOST',
            'host_id': 'shared-host-id',
        }

        results = []
        for i in range(3):
            alert = dict(base_alert, name=f"Suspicious Activity {i}")
            results.append(await service.ingest_alert(alert, 'crowdstrike'))

        assert all(r['status'] == 'accepted' for r in results)

        host_risk_entries = [
            entry
            for r in results
            for entry in r['entity_risk']
            if entry['entity_type'] == 'host'
        ]
        assert len(host_risk_entries) == 3
        assert host_risk_entries[0]['promoted'] is False
        assert host_risk_entries[-1]['promoted'] is True
        assert host_risk_entries[-1]['newly_promoted'] is True

    @pytest.mark.asyncio
    async def test_single_low_severity_alert_does_not_promote(self):
        service = AlertIntakeService()

        alert = {
            'timestamp': int(datetime.utcnow().timestamp() * 1000),
            'name': 'Minor Info Event',
            'severity': 1,  # maps to INFORMATIONAL
            'event_type': 'dns_query',
            'user_id': 'user-b',
            'computer_name': 'QUIET-HOST',
            'host_id': 'quiet-host-id',
        }

        result = await service.ingest_alert(alert, 'crowdstrike')
        assert all(not entry['promoted'] for entry in result['entity_risk'])
