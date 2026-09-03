"""Tests for local threat-intel grounding (Phase A)."""

import asyncio
import pytest

from backend.services.threat_intel.local_feeds import LocalThreatIntelDB, DEFAULT_FEED_DIR
from backend.services.triage.skill_handlers import TriageSkillExecutor


@pytest.fixture
def db():
    """Create a fresh LocalThreatIntelDB loaded from the real vendored feeds."""
    instance = LocalThreatIntelDB(feed_dir=DEFAULT_FEED_DIR)
    instance.load_all()
    return instance


def test_load_all_returns_nonzero_counts_for_every_vendored_category(db):
    counts = db.stats()
    assert counts.get("ransomware_extension", 0) > 0
    assert counts.get("ransomware_note", 0) > 0
    assert counts.get("suspicious_port", 0) > 0
    assert counts.get("suspicious_mutex", 0) > 0


def test_load_all_is_idempotent(db):
    """Reloading must not duplicate rows."""
    first = db.load_all()
    second = db.load_all()
    assert first == second


def test_lookup_extension_matches_known_ransomware_extension(db):
    match = db.lookup_extension("report.docx.locky")
    assert match is not None
    assert match.matched is True
    assert match.category == "ransomware_extension"
    assert match.source == "local_threat_intel_db"
    assert match.confidence > 0.9


def test_lookup_extension_is_case_insensitive(db):
    match = db.lookup_extension("REPORT.DOCX.LOCKY")
    assert match is not None
    assert match.category == "ransomware_extension"


def test_lookup_extension_no_match_for_benign_file(db):
    assert db.lookup_extension("notes.txt") is None
    assert db.lookup_extension("raindrop.ps1") is None


def test_lookup_ransomware_note_matches_known_filename(db):
    match = db.lookup_ransomware_note("CONTI_README.txt")
    assert match is not None
    assert match.category == "ransomware_note"


def test_lookup_ransomware_note_no_match_for_benign_filename(db):
    assert db.lookup_ransomware_note("normal_file.txt") is None


def test_lookup_port_matches_known_suspicious_port(db):
    match = db.lookup_port(3389)
    assert match is not None
    assert match.category == "suspicious_port"


def test_lookup_port_no_match_for_unlisted_port(db):
    # 999999 is not a valid TCP/UDP port (valid range is 0-65535), so it can never
    # legitimately appear in any real "suspicious ports" feed -- unlike a plausible-looking
    # port number (e.g. 9999), which upstream feed updates could add over time now that
    # Phase D live-fetches the real, larger upstream list instead of a small static subset.
    assert db.lookup_port(999999) is None


def test_lookup_mutex_matches_known_malware_mutex(db):
    match = db.lookup_mutex("Global\\MsWinZonesCacheCounterMutexA")
    assert match is not None
    assert match.category == "suspicious_mutex"


def test_lookup_mutex_no_match_for_random_name(db):
    assert db.lookup_mutex("SomeRandomMutex123") is None


def test_lookup_keyword_generic_category_lookup(db):
    match = db.lookup_keyword("Global\\MsWinZonesCacheCounterMutexA", "suspicious_mutex")
    assert match is not None
    assert match.category == "suspicious_mutex"


class TestSeverityEvaluatorGrounding:
    """Validates the motivating Phase A bug fix: a known ransomware indicator must be
    scored CRITICAL deterministically, bypassing keyword/LLM heuristics entirely.
    """

    def test_ransomware_extension_forces_critical_severity(self):
        alert_data = {
            "alert_name": "Suspicious file activity",
            "file_path": "C:\\Users\\victim\\Documents\\report.docx.locky",
        }
        result = asyncio.run(
            TriageSkillExecutor.execute_skill("severity-evaluator", {"alert_data": alert_data})
        )
        assert result["status"] == "success"
        assert result["severity"] == "critical"
        assert result["risk_score"] >= 0.9
        assert result["requires_immediate_action"] is True
        assert result["grounded"] is True
        assert result["grounding_source"] == "local_threat_intel_db"

    def test_ransomware_note_forces_critical_severity(self):
        alert_data = {"alert_name": "New file created", "file_name": "CONTI_README.txt"}
        result = asyncio.run(
            TriageSkillExecutor.execute_skill("severity-evaluator", {"alert_data": alert_data})
        )
        assert result["severity"] == "critical"
        assert result["grounded"] is True

    def test_benign_alert_falls_back_to_heuristic_ungrounded(self):
        alert_data = {"alert_name": "user logged in", "file_path": "notes.txt"}
        result = asyncio.run(
            TriageSkillExecutor.execute_skill("severity-evaluator", {"alert_data": alert_data})
        )
        assert result["grounded"] is False
        assert result["severity"] == "low"


class TestIocExtractorGrounding:
    def test_extracted_file_is_tagged_with_threat_intel_match(self):
        raw_alert = {
            "alert_name": "Suspicious file activity",
            "file_path": "C:\\Users\\victim\\Documents\\report.docx.locky",
        }
        result = asyncio.run(
            TriageSkillExecutor.execute_skill("ioc-extractor", {"raw_alert": raw_alert})
        )
        assert result["status"] == "success"
        matches = result["threat_intel_matches"]
        assert len(matches) == 1
        assert matches[0]["indicator_type"] == "ransomware_extension"
        assert matches[0]["source"] == "local_threat_intel_db"


class TestThreatIntelPrefilterGrounding:
    def test_suspicious_port_and_mutex_are_flagged(self):
        input_data = {
            "entities": {
                "ports": [3389],
                "processes": ["Global\\MsWinZonesCacheCounterMutexA"],
            }
        }
        result = asyncio.run(
            TriageSkillExecutor.execute_skill("threat-intel-prefilter", input_data)
        )
        assert result["prefilter_verdict"] == "MALICIOUS_FOUND"
        types_found = {f["type"] for f in result["flagged_iocs"]}
        assert "port" in types_found
        assert "mutex" in types_found

    def test_clean_entities_produce_no_flags(self):
        input_data = {
            "entities": {
                "ips": ["10.0.0.5"],
                "domains": ["internal.company.com"],
                "ports": [443],
                "processes": ["notepad.exe"],
            }
        }
        result = asyncio.run(
            TriageSkillExecutor.execute_skill("threat-intel-prefilter", input_data)
        )
        assert result["prefilter_verdict"] == "CLEAN"
        assert result["flagged_count"] == 0
