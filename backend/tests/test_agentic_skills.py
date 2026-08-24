"""Tests for the Agentic Skill Catalog & Execution Framework across Triage, Evidence, and Compression."""

import pytest
import asyncio
from backend.services.skills import skill_registry, SOCSkill, UniversalSkillRegistry
from backend.services.evidence.skill_handlers import EvidenceSkillExecutor
from backend.services.compression.skill_handlers import CompressionSkillExecutor
from backend.services.investigation_context import InvestigationContext
from backend.services.orchestrator import TriageAgent, EvidenceAgent, CompressionAgent


class TestUniversalSkillLoader:
    """Test suite for UniversalSkillRegistry."""

    def test_load_all_phases_skills(self):
        """Verify skills are discovered across triage, evidence, compression, and discovery."""
        skill_registry.clear_cache()
        all_skills = skill_registry.load_all_skills()
        assert len(all_skills) >= 20  # 4 triage + 6 evidence + 5 compression + 8 discovery

        triage_skills = skill_registry.load_phase_skills("triage")
        assert len(triage_skills) >= 4
        triage_names = [s.name for s in triage_skills]
        assert "ioc-extractor" in triage_names
        assert "mitre-classifier" in triage_names
        assert "severity-evaluator" in triage_names
        assert "grounding-validator" in triage_names

        evidence_skills = skill_registry.load_phase_skills("evidence")
        assert len(evidence_skills) >= 6
        evidence_names = [s.name for s in evidence_skills]
        assert "edr-process-tree" in evidence_names
        assert "network-flow-analyzer" in evidence_names
        assert "identity-ad-lookup" in evidence_names
        assert "threat-intel-lookup" in evidence_names
        assert "file-forensics" in evidence_names
        assert "persistence-auditor" in evidence_names

        compression_skills = skill_registry.load_phase_skills("compression")
        assert len(compression_skills) >= 5
        compression_names = [s.name for s in compression_skills]
        assert "temporal-clustering" in compression_names
        assert "entity-graph-reduction" in compression_names
        assert "behavioral-anomaly-filter" in compression_names
        assert "semantic-summarizer" in compression_names
        assert "duplicate-rollup" in compression_names

    def test_skill_attribute_matching(self):
        """Verify skills can be queried by collection and action tags."""
        skills = skill_registry.find_skills_for_actions(["process_tree"], phase="evidence")
        assert len(skills) >= 1
        assert skills[0].name == "edr-process-tree"

        intel_skills = skill_registry.find_skills_for_actions(["reputation_score"], phase="evidence")
        assert len(intel_skills) >= 1
        assert intel_skills[0].name == "threat-intel-lookup"


class TestEvidenceSkillHandlers:
    """Test suite for EvidenceSkillExecutor."""

    @pytest.mark.asyncio
    async def test_edr_process_tree_skill(self):
        """Test process tree evidence collection for suspicious and benign binaries."""
        res_mal = await EvidenceSkillExecutor.execute_skill("edr-process-tree", "install.sh", "file")
        assert res_mal["risk_score"] > 0.5
        assert "command_line" in res_mal["enrichment_data"] or "total_audit_events" in res_mal["enrichment_data"]

        res_benign = await EvidenceSkillExecutor.execute_skill("edr-process-tree", "explorer.exe", "process")
        assert res_benign["risk_score"] <= 0.5

    @pytest.mark.asyncio
    async def test_network_flow_skill(self):
        """Test network flow evidence analyzer on C2 IP and internal host."""
        res_c2 = await EvidenceSkillExecutor.execute_skill("network-flow-analyzer", "192.42.1.174", "ip")
        assert "enrichment_data" in res_c2
        assert res_c2["enrichment_data"]["target_ip"] == "192.42.1.174"
        assert res_c2["risk_score"] >= 0.1

    @pytest.mark.asyncio
    async def test_identity_ad_skill(self):
        """Test active directory identity lookup for root / privileged accounts."""
        res_root = await EvidenceSkillExecutor.execute_skill("identity-ad-lookup", "root", "user")
        assert res_root["enrichment_data"]["privileged"] is True
        assert res_root["risk_score"] >= 0.1

    @pytest.mark.asyncio
    async def test_file_forensics_skill(self):
        """Test file forensics on file entities."""
        res_enc = await EvidenceSkillExecutor.execute_skill("file-forensics", "donotcry", "file")
        assert res_enc["enrichment_data"]["file_name"] == "donotcry"
        assert "risk_score" in res_enc
        assert "threat_intel" in res_enc


class TestAgenticPipelineExecution:
    """Integration test suite for agentic execution with skills."""

    @pytest.mark.asyncio
    async def test_evidence_agent_with_skills(self):
        """Verify EvidenceAgent deploys targeted skills per entity type and reports skills_used."""
        ctx = InvestigationContext(
            alert_data={"alert_id": "test-alert-001", "computer_name": "linuxshare", "ip_address": "192.42.1.174"},
            entities=[
                {"type": "host", "id": "linuxshare"},
                {"type": "ip", "id": "192.42.1.174"},
                {"type": "file", "id": "donotcry"},
                {"type": "user", "id": "root"},
            ],
            classification="malware_execution"
        )
        agent = EvidenceAgent()
        report = await agent.execute({}, ctx)

        assert report.status.value == "completed"
        assert len(report.findings["skills_used"]) >= 3
        assert "edr-process-tree" in report.findings["skills_used"]
        assert "threat-intel-lookup" in report.findings["skills_used"]
        assert len(ctx.entity_graph) >= 4

    @pytest.mark.asyncio
    async def test_compression_agent_with_skills(self):
        """Verify CompressionAgent applies 7-stage pipeline and reports compression skills_used."""
        ctx = InvestigationContext(
            alert_data={"alert_id": "test-alert-001", "computer_name": "linuxshare", "timestamp": "2026-08-20T14:46:00Z"},
            entities=[{"type": "host", "id": "linuxshare"}, {"type": "ip", "id": "192.42.1.174"}],
            classification="malware_execution",
            severity="Critical"
        )
        agent = CompressionAgent()
        report = await agent.execute({}, ctx)

        assert report.status.value == "completed"
        assert "skills_used" in report.findings
        assert "duplicate-rollup" in report.findings["skills_used"]
        assert "temporal-clustering" in report.findings["skills_used"]
        assert ctx.compressed_events["compression_ratio"].endswith("x")
