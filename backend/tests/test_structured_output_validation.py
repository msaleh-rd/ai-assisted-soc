"""Tests for structured-output validation (Wave 1 / Phase D, Step 4)."""

import pytest

from backend.services.llm_client import validate_triage_output, TriageOutput, Entity


def _make_output(**overrides):
    defaults = dict(
        severity="High",
        classification="malware_execution",
        tactic="Execution",
        technique="T1204",
        entities_identified=[Entity(type="host", id="HOST-001")],
        requires_immediate_action=True,
        initial_assessment="Suspicious process execution detected.",
        confidence=0.85,
    )
    defaults.update(overrides)
    return defaults


class TestValidateTriageOutput:
    def test_valid_output_has_no_violations(self):
        output = TriageOutput(**_make_output())
        assert validate_triage_output(output) == []

    def test_invalid_severity_is_flagged(self):
        output = TriageOutput(**_make_output(severity="Extreme"))
        violations = validate_triage_output(output)
        assert any("severity" in v for v in violations)

    def test_confidence_above_one_is_flagged(self):
        # TriageOutput's Pydantic field already constrains confidence to [0,1], so
        # use model_construct() to bypass validation and exercise the defense-in-depth
        # check in validate_triage_output() directly.
        output = TriageOutput.model_construct(**_make_output(confidence=1.5))
        violations = validate_triage_output(output)
        assert any("confidence" in v for v in violations)

    def test_confidence_below_zero_is_flagged(self):
        output = TriageOutput.model_construct(**_make_output(confidence=-0.1))
        violations = validate_triage_output(output)
        assert any("confidence" in v for v in violations)

    def test_unrecognized_entity_type_is_flagged(self):
        output = TriageOutput(**_make_output(entities_identified=[Entity(type="spaceship", id="X-Wing")]))
        violations = validate_triage_output(output)
        assert any("entity type" in v for v in violations)

    def test_severity_is_case_insensitive(self):
        output = TriageOutput(**_make_output(severity="CRITICAL"))
        assert validate_triage_output(output) == []
