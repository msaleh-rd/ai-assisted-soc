"""Tests for the AI Governance API (backend/api/routes/ai_governance.py) —
the read-only visibility surface exposing Wave 1-3 subsystems (Detection-as-
Code, Entity-Risk, Maturity Gate, Playbook Engine, Compounding Memory,
Self-Play Purple Team) that previously had no HTTP-reachable surface at all.

Mounts the router on a minimal standalone FastAPI app (not backend.main's
full `app`) so these tests never depend on live Postgres/Neo4j connectivity —
consistent with this module's own read-only, DB-optional design.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.routes import ai_governance
from backend.services.entity_risk import entity_risk_tracker
from backend.services.memory.distillation import compounding_memory
from backend.services.self_play import purple_team as purple_team_module


@pytest.fixture(autouse=True)
def _clean_singletons():
    """Avoid cross-test-file state leakage on the module-level singletons."""
    entity_risk_tracker.clear()
    compounding_memory.clear()
    yield
    entity_risk_tracker.clear()
    compounding_memory.clear()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(ai_governance.router)
    return TestClient(app)


class TestDetectionsEndpoint:
    def test_list_detection_rules_returns_real_vendored_rules(self, client):
        resp = client.get("/api/v1/ai-governance/detections")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 3  # 3 real starter rules vendored in Phase H
        assert all({"id", "name", "severity", "category", "enabled"} <= r.keys() for r in data["rules"])


class TestEntityRiskEndpoint:
    def test_empty_by_default(self, client):
        resp = client.get("/api/v1/ai-governance/entity-risk")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_tracked"] == 0
        assert data["entities"] == []

    def test_reflects_recorded_alerts(self, client):
        entity_risk_tracker.record_alert("host-1", "host", "alert-1", 0.9)
        resp = client.get("/api/v1/ai-governance/entity-risk")
        data = resp.json()
        assert data["total_tracked"] == 1
        assert data["entities"][0]["entity_id"] == "host-1"
        assert data["entities"][0]["cumulative_risk"] > 0


class TestMaturityGateEndpoint:
    def test_returns_current_tier_and_all_skills(self, client):
        resp = client.get("/api/v1/ai-governance/maturity-gate")
        assert resp.status_code == 200
        data = resp.json()
        assert "current_tier" in data
        names = {s["skill_name"] for s in data["skills"]}
        assert "isolate-host" in names
        isolate = next(s for s in data["skills"] if s["skill_name"] == "isolate-host")
        assert isolate["blast_radius"] == "CRITICAL"


class TestPlaybooksEndpoint:
    def test_lists_real_vendored_playbook(self, client):
        resp = client.get("/api/v1/ai-governance/playbooks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        ids = {p["id"] for p in data["playbooks"]}
        assert any("ransomware" in pid for pid in ids)


class TestMemoryPriorsEndpoint:
    def test_empty_by_default(self, client):
        resp = client.get("/api/v1/ai-governance/memory/priors")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_distill_endpoint_runs_without_db(self, client):
        resp = client.post("/api/v1/ai-governance/memory/distill")
        assert resp.status_code == 200
        assert resp.json()["signatures_processed"] == 0


class TestPurpleTeamEndpoints:
    def test_list_campaigns(self, client):
        resp = client.get("/api/v1/ai-governance/purple-team/campaigns")
        assert resp.status_code == 200
        names = {c["name"] for c in resp.json()["campaigns"]}
        assert "ransomware_chain" in names
        assert "credential_theft_chain" in names

    def test_unknown_campaign_returns_404(self, client):
        resp = client.post("/api/v1/ai-governance/purple-team/run", json={"campaign_name": "nonexistent"})
        assert resp.status_code == 404

    def test_run_campaign_files_drafts_to_tmp_dir(self, client, tmp_path, monkeypatch):
        # Redirect draft-rule filing to a tmp dir so this test never touches
        # the real backend/detections/drafts/ directory (mirrors
        # test_purple_team.py's existing precedent).
        class _TmpDirCampaign(purple_team_module.SelfPlayCampaign):
            def __init__(self):
                super().__init__(draft_rules_dir=tmp_path)

        monkeypatch.setattr(purple_team_module, "SelfPlayCampaign", _TmpDirCampaign)

        resp = client.post(
            "/api/v1/ai-governance/purple-team/run",
            json={"campaign_name": "credential_theft_chain"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["campaign_name"] == "credential_theft_chain"
        assert len(data["technique_results"]) == 4
        assert 0.0 <= data["coverage_percentage"] <= 100.0


class TestOverviewEndpoint:
    def test_returns_aggregate_summary(self, client):
        resp = client.get("/api/v1/ai-governance/overview")
        assert resp.status_code == 200
        data = resp.json()
        assert data["detection_rules_total"] >= 3
        assert data["playbooks_loaded"] >= 1
        assert "automation_tier" in data
