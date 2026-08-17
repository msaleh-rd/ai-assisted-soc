"""Evaluation harness for LLM agents and RAG retrieval.

Run with: pytest backend/tests/test_llm_evaluation.py -m llm
Run RAG only: pytest backend/tests/test_llm_evaluation.py -k test_rag
"""

import os
import json
import pytest

from backend.services.rag_service import search_playbook
from backend.services.orchestrator import TriageAgent

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_FILE = os.path.join(BASE_DIR, "tests", "fixtures", "sample_alerts.json")


def load_fixtures():
    with open(FIXTURES_FILE, "r") as f:
        return json.load(f)


# ======================================================================
# 1. RAG Retrieval Tests (Fast, no LLM required)
# ======================================================================

def test_rag_malware_retrieval():
    """Verify that querying for malware execution returns the right section."""
    docs = search_playbook(query="malware execution payload", classification="malware_execution")
    assert len(docs) > 0, "No documents retrieved"
    
    # The first document should be from the Malware Execution playbook
    top_doc = docs[0]
    assert "Malware Execution" in top_doc.metadata.get("playbook_name", ""), "Wrong playbook ranked first"
    
    # Should prioritize Containment Actions
    section = top_doc.metadata.get("section_title", "").lower()
    assert "containment" in section, "Containment section should be highest priority"


def test_rag_no_cross_contamination():
    """Verify that filtering by classification ignores irrelevant playbooks."""
    docs = search_playbook(query="phishing email link clicked", classification="phishing_response")
    
    # Check that malware playbook wasn't mistakenly prioritized
    for doc in docs[:2]:
        assert "Phishing" in doc.metadata.get("playbook_name", ""), "RAG pulled wrong playbook type"


# ======================================================================
# 2. LLM Agent Tests (Slow, requires LM Studio running)
# ======================================================================

@pytest.fixture
def fixtures():
    return load_fixtures()

@pytest.mark.llm
@pytest.mark.asyncio
async def test_triage_malware(fixtures):
    fixture = next(f for f in fixtures if f["id"] == "alert_malware_1")
    agent = TriageAgent()
    
    report = await agent.execute(inputs={"alert": fixture["alert_data"]}, context={})
    
    findings = report.findings
    assert findings.get("error") is None, f"LLM error: {findings.get('error')}"
    assert findings["classification"] == fixture["expected_classification"]
    assert findings["severity"].lower() == fixture["expected_severity"].lower()
    
    # Check entity extraction
    entities = findings.get("entities_identified", [])
    entity_types = {e["type"] for e in entities}
    assert "user" in entity_types
    assert "host" in entity_types
    assert "file" in entity_types


@pytest.mark.llm
@pytest.mark.asyncio
async def test_triage_lateral_movement(fixtures):
    fixture = next(f for f in fixtures if f["id"] == "alert_lateral_1")
    agent = TriageAgent()
    
    report = await agent.execute(inputs={"alert": fixture["alert_data"]}, context={})
    
    findings = report.findings
    assert findings.get("error") is None
    assert findings["classification"] == fixture["expected_classification"]
    
    entities = findings.get("entities_identified", [])
    entity_types = {e["type"] for e in entities}
    assert "host" in entity_types


@pytest.mark.llm
@pytest.mark.asyncio
async def test_triage_phishing(fixtures):
    fixture = next(f for f in fixtures if f["id"] == "alert_phishing_1")
    agent = TriageAgent()
    
    report = await agent.execute(inputs={"alert": fixture["alert_data"]}, context={})
    
    findings = report.findings
    assert findings.get("error") is None
    assert findings["classification"] == fixture["expected_classification"]
    
    entities = findings.get("entities_identified", [])
    entity_types = {e["type"] for e in entities}
    assert "user" in entity_types
