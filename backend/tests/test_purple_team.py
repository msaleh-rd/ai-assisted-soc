"""Tests for the Self-Play Purple Team (Wave 3, Phase L)."""

from pathlib import Path

from backend.services.detection_engine import DetectionEngine, DetectionRule, DetectionCondition, DetectionRuleLoader
from backend.services.self_play.purple_team import (
    CANNED_CAMPAIGNS,
    SelfPlayCampaign,
    CampaignResult,
)


class TestCannedCampaigns:
    def test_ransomware_chain_has_expected_technique_sequence(self):
        steps = CANNED_CAMPAIGNS["ransomware_chain"]
        assert [s.technique_id for s in steps] == ["T1566.001", "T1059.001", "T1547.001", "T1486"]

    def test_credential_theft_chain_has_expected_technique_sequence(self):
        steps = CANNED_CAMPAIGNS["credential_theft_chain"]
        assert [s.technique_id for s in steps] == ["T1078", "T1003", "T1021.001", "T1048"]

    def test_every_step_has_a_synthetic_event_with_event_type(self):
        for campaign in CANNED_CAMPAIGNS.values():
            for step in campaign:
                assert "event_type" in step.synthetic_event


class TestRunCampaignAgainstRealRuleset:
    """Uses the actual vendored Phase H ruleset (no injected rules) -- today,
    none of the 3 real rules (credential-stuffing, high-risk-score, suspicious-
    port) cover any of these campaign techniques, so this honestly exercises
    the 0%-coverage / full-draft-filing path."""

    def test_ransomware_chain_reports_coverage_and_draft_files(self, tmp_path):
        campaign = SelfPlayCampaign(draft_rules_dir=tmp_path)
        result = campaign.run_campaign("ransomware_chain")

        assert isinstance(result, CampaignResult)
        assert result.campaign_name == "ransomware_chain"
        assert len(result.technique_results) == 4
        assert 0.0 <= result.coverage_percentage <= 100.0
        # None of today's 3 real rules match these synthetic events.
        assert result.coverage_percentage == 0.0
        assert len(result.draft_rules_filed) == 4
        for r in result.technique_results:
            assert r.detected is False
            assert r.detection_latency_ms >= 0.0

    def test_draft_rule_files_are_valid_and_disabled(self, tmp_path):
        campaign = SelfPlayCampaign(draft_rules_dir=tmp_path)
        result = campaign.run_campaign("ransomware_chain")

        loaded_rules = DetectionRuleLoader.load_all(tmp_path)
        assert len(loaded_rules) == len(result.draft_rules_filed)
        for rule in loaded_rules:
            assert rule.enabled is False
            assert "self-play-draft" in rule.tags
            assert any(t.startswith("mitre.attack.") for t in rule.tags)
            # A disabled draft rule must never fire, even against its own
            # triggering event.
            assert rule.evaluate({"anything": "at all"}) is False

    def test_unknown_campaign_name_raises(self, tmp_path):
        campaign = SelfPlayCampaign(draft_rules_dir=tmp_path)
        try:
            campaign.run_campaign("not_a_real_campaign")
            assert False, "expected ValueError"
        except ValueError as e:
            assert "Unknown campaign" in str(e)


class TestRunCampaignWithPartialCoverage:
    """Injects a custom rule that DOES match one technique-step, to verify the
    engine correctly reports partial coverage and only files drafts for the
    remaining uncovered techniques."""

    def _make_engine_with_procdump_rule(self) -> DetectionEngine:
        rule = DetectionRule(
            id="test-credential-dumping",
            name="Test: Credential Dumping via procdump",
            severity="high",
            category="identity",
            tags=["mitre.attack.T1003"],
            log_source="edr",
            condition_mode="any",
            conditions=[DetectionCondition(field="command_line", op="contains", value="procdump")],
            enabled=True,
        )
        return DetectionEngine(rules=[rule])

    def test_credential_theft_chain_partial_coverage(self, tmp_path):
        engine = self._make_engine_with_procdump_rule()
        campaign = SelfPlayCampaign(engine=engine, draft_rules_dir=tmp_path)

        result = campaign.run_campaign("credential_theft_chain")

        by_technique = {r.technique_id: r for r in result.technique_results}
        assert by_technique["T1003"].detected is True
        assert "test-credential-dumping" in by_technique["T1003"].matched_rule_ids
        assert by_technique["T1078"].detected is False
        assert by_technique["T1021.001"].detected is False
        assert by_technique["T1048"].detected is False

        assert result.coverage_percentage == 25.0  # 1 of 4 techniques covered
        # Drafts filed only for the 3 uncovered techniques, not T1003.
        assert len(result.draft_rules_filed) == 3
        filed_technique_ids = {Path(p).stem.split("draft-")[1].rsplit("-", 1)[0] for p in result.draft_rules_filed}
        assert "t1003" not in filed_technique_ids
