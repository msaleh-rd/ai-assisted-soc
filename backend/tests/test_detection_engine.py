"""Tests for the Detection-as-Code engine (Wave 2 / Phase H, Steps 1-2)."""

import pytest

from backend.services.detection_engine import (
    DetectionCondition,
    DetectionRule,
    DetectionRuleLoader,
    DetectionEngine,
)


class TestDetectionCondition:
    def test_equals_matches(self):
        cond = DetectionCondition(field="event_type", op="equals", value="login_failure")
        assert cond.evaluate({"event_type": "login_failure"}) is True
        assert cond.evaluate({"event_type": "login_success"}) is False

    def test_gte_matches(self):
        cond = DetectionCondition(field="risk_score", op="gte", value=0.6)
        assert cond.evaluate({"risk_score": 0.6}) is True
        assert cond.evaluate({"risk_score": 0.59}) is False

    def test_missing_field_does_not_match_numeric_ops(self):
        cond = DetectionCondition(field="risk_score", op="gte", value=0.6)
        assert cond.evaluate({}) is False

    def test_contains_op(self):
        cond = DetectionCondition(field="command_line", op="contains", value="-enc")
        assert cond.evaluate({"command_line": "powershell.exe -enc AAA"}) is True
        assert cond.evaluate({"command_line": "notepad.exe"}) is False

    def test_in_list_op(self):
        cond = DetectionCondition(field="port", op="in_list", value=[4444, 8080])
        assert cond.evaluate({"port": 4444}) is True
        assert cond.evaluate({"port": 22}) is False

    def test_regex_op(self):
        cond = DetectionCondition(field="filename", op="regex", value=r"\.locky$")
        assert cond.evaluate({"filename": "report.docx.locky"}) is True
        assert cond.evaluate({"filename": "notes.txt"}) is False


class TestDetectionRule:
    def _make_rule(self, mode="all"):
        return DetectionRule(
            id="test-rule",
            name="Test Rule",
            severity="high",
            category="test",
            condition_mode=mode,
            conditions=[
                DetectionCondition(field="a", op="equals", value=1),
                DetectionCondition(field="b", op="equals", value=2),
            ],
        )

    def test_all_mode_requires_every_condition(self):
        rule = self._make_rule("all")
        assert rule.evaluate({"a": 1, "b": 2}) is True
        assert rule.evaluate({"a": 1, "b": 3}) is False

    def test_any_mode_requires_one_condition(self):
        rule = self._make_rule("any")
        assert rule.evaluate({"a": 1, "b": 999}) is True
        assert rule.evaluate({"a": 999, "b": 999}) is False

    def test_disabled_rule_never_matches(self):
        rule = self._make_rule("all")
        rule.enabled = False
        assert rule.evaluate({"a": 1, "b": 2}) is False

    def test_rule_with_no_conditions_never_matches(self):
        rule = DetectionRule(id="empty", name="Empty", severity="low", category="test")
        assert rule.evaluate({"anything": True}) is False


class TestVendoredDetectionRulesPassFixtures:
    """Every real rule under backend/detections/ must match its positive
    fixtures and must NOT match its negative fixtures (Phase H, Step 4's
    fixture-replay CI gate, exercised here directly)."""

    @pytest.fixture(scope="class")
    def rules(self):
        loaded = DetectionRuleLoader.load_all()
        assert len(loaded) >= 3, "Expected at least the 3 authored starter rules"
        return loaded

    def test_every_rule_matches_all_positive_fixtures(self, rules):
        for rule in rules:
            fixtures = DetectionRuleLoader.load_fixtures(rule)
            for event in fixtures["positive"]:
                assert rule.evaluate(event) is True, f"{rule.id} failed to match its own positive fixture: {event}"

    def test_every_rule_rejects_all_negative_fixtures(self, rules):
        for rule in rules:
            fixtures = DetectionRuleLoader.load_fixtures(rule)
            for event in fixtures["negative"]:
                assert rule.evaluate(event) is False, f"{rule.id} incorrectly matched its negative fixture: {event}"

    def test_credential_stuffing_ai_evasion_rule_exists_with_correct_tags(self, rules):
        rule = next(r for r in rules if r.id == "credential-stuffing-ai-evasion")
        assert rule.severity == "high"
        assert "mitre.attack.T1110" in rule.tags
        assert "mitre.attack.T1110.004" in rule.tags


class TestDetectionEngineMatchEvent:
    def test_match_event_returns_matching_rules_only(self):
        rules = [
            DetectionRule(
                id="r1", name="R1", severity="high", category="test",
                conditions=[DetectionCondition(field="x", op="equals", value=1)],
            ),
            DetectionRule(
                id="r2", name="R2", severity="low", category="test",
                conditions=[DetectionCondition(field="x", op="equals", value=999)],
            ),
        ]
        engine = DetectionEngine(rules=rules)
        matches = engine.match_event({"x": 1})
        assert len(matches) == 1
        assert matches[0].rule_id == "r1"

    def test_get_rule_by_id(self):
        rules = [DetectionRule(id="r1", name="R1", severity="high", category="test")]
        engine = DetectionEngine(rules=rules)
        assert engine.get_rule("r1") is not None
        assert engine.get_rule("does-not-exist") is None
