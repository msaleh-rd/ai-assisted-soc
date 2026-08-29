"""Unit tests for the TriageSkillExecutor."""

import pytest
import asyncio
from backend.services.triage.skill_handlers import TriageSkillExecutor


def test_ioc_extractor_skill():
    async def run_test():
        raw_alert = {
            "name": "Ransomware Alert",
            "source_ip": "192.168.1.50",
            "remote_ip": "192.42.1.174",
            "user": "victim_user",
            "host": "workstation-01",
            "file": "donotcry.exe",
            "domain": "malicious-c2.com",
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
        res = await TriageSkillExecutor.execute_skill("ioc-extractor", {"raw_alert": raw_alert})
        assert res["status"] == "success"
        entities = res["entities"]
        assert "192.168.1.50" in entities["ips"]
        assert "192.42.1.174" in entities["ips"]
        assert "victim_user" in entities["users"]
        assert "workstation-01" in entities["hosts"]
        assert "donotcry.exe" in entities["files"]
        assert "malicious-c2.com" in entities["domains"]
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in entities["hashes"]

    asyncio.run(run_test())


def test_mitre_classifier_skill():
    async def run_test():
        alert_data = {
            "alert_name": "Suspicious Execve Process Execution",
            "event_type": "execve"
        }
        res = await TriageSkillExecutor.execute_skill("mitre-classifier", {"alert_data": alert_data})
        assert res["status"] == "success"
        assert "technique" in res
        assert "tactic" in res

    asyncio.run(run_test())


def test_severity_evaluator_skill():
    async def run_test():
        alert_critical = {"alert_name": "Active donotcry ransomware outbreak"}
        res_crit = await TriageSkillExecutor.execute_skill("severity-evaluator", {"alert_data": alert_critical})
        assert res_crit["severity"] == "critical"
        assert res_crit["requires_immediate_action"] is True

        alert_low = {"alert_name": "Routine routine ping"}
        res_low = await TriageSkillExecutor.execute_skill("severity-evaluator", {"alert_data": alert_low})
        assert res_low["severity"] == "low"
        assert res_low["requires_immediate_action"] is False

    asyncio.run(run_test())


def test_grounding_validator_skill():
    async def run_test():
        extracted = [{"value": "192.168.1.10"}, {"value": "hallucinated_ip.com"}]
        raw_text = "Alert triggered on host 192.168.1.10 connecting to internal server"
        res = await TriageSkillExecutor.execute_skill("grounding-validator", {
            "extracted_entities": extracted,
            "raw_alert_text": raw_text
        })
        assert res["status"] == "success"
        assert len(res["validated_entities"]) == 1
        assert len(res["dropped_entities"]) == 1
        assert res["hallucination_rate"] == 0.5

    asyncio.run(run_test())
