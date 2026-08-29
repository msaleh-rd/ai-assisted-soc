"""Unit tests for Phase 3 Response Skills and ResponseSkillExecutor."""

import pytest
from backend.services.response.skill_handlers import ResponseSkillExecutor
from backend.services.skills import skill_registry


@pytest.mark.asyncio
async def test_response_skills_discovery():
    """Verify that response skills are discovered and loaded from filesystem."""
    skills = skill_registry.load_phase_skills("response")
    skill_names = {s.name for s in skills}
    
    assert "isolate-host" in skill_names
    assert "block-ip" in skill_names
    assert "block-domain" in skill_names
    assert "kill-process" in skill_names
    assert "reset-credentials" in skill_names


@pytest.mark.asyncio
async def test_isolate_host_skill():
    """Test host network isolation skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="isolate-host",
        target="workstation-99",
        parameters={"reason": "Active ransomware spreading"}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "isolated" in res["result"]
    assert "rule_id" in res


@pytest.mark.asyncio
async def test_block_ip_skill():
    """Test firewall IP block skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="block-ip",
        target="192.42.1.174",
        parameters={"direction": "both"}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "192.42.1.174" in res["result"]
    assert "rule_id" in res


@pytest.mark.asyncio
async def test_block_domain_skill():
    """Test DNS sinkhole domain block skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="block-domain",
        target="malicious-c2-server.com",
        parameters={}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "sinkhole" in res["result"]


@pytest.mark.asyncio
async def test_kill_process_skill():
    """Test process termination skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="kill-process",
        target="donotcry",
        parameters={"pids": [4096], "host": "linuxshare"}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "donotcry" in res["result"]
    assert 4096 in res["terminated_pids"]


@pytest.mark.asyncio
async def test_reset_credentials_skill():
    """Test account credential revocation skill execution."""
    res = await ResponseSkillExecutor.execute_skill(
        skill_name="reset-credentials",
        target="compromised_user",
        parameters={}
    )
    assert res["success"] is True
    assert res["status"] == "completed"
    assert "compromised_user" in res["result"]
    assert res["sessions_revoked"] > 0
