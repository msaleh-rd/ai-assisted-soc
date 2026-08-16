from typing import List, Dict, Any, Literal
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
import os

# Base URL for local LM Studio
LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://127.0.0.1:1234/v1")
# Model identifier can be anything or specifically match the loaded model
MODEL_NAME = os.getenv("LLM_MODEL", "qwen2.5-7b-instruct")

def get_llm():
    """Returns a configured LangChain ChatOpenAI instance pointing to local LM Studio."""
    return ChatOpenAI(
        base_url=LM_STUDIO_URL,
        api_key="lm-studio",  # API key is ignored by LM Studio but required by the client
        model=MODEL_NAME,
        temperature=0.1,  # Low temperature for deterministic security analysis
        max_tokens=1024
    )


# ---------------------------------------------------------------------------
# Structured Output Schemas
# ---------------------------------------------------------------------------

class Entity(BaseModel):
    type: str = Field(description="Type of entity, e.g., 'user', 'host', 'ip', 'file', 'process', 'domain'")
    id: str = Field(description="The unique identifier or value of the entity")

class TriageOutput(BaseModel):
    """Schema for the TriageAgent's structured output."""
    severity: str = Field(description="Severity level: 'Critical', 'High', 'Medium', 'Low'")
    classification: str = Field(description="Classification of the alert, e.g., 'malware_execution', 'lateral_movement'")
    tactic: str = Field(description="MITRE ATT&CK tactic, if applicable")
    technique: str = Field(description="MITRE ATT&CK technique or technique ID, if applicable")
    entities_identified: List[Entity] = Field(description="List of entities extracted from the raw alert")
    requires_immediate_action: bool = Field(description="True if the alert severity is High or Critical")
    initial_assessment: str = Field(description="A 1-2 sentence human-readable summary of the alert")


class RCAOutput(BaseModel):
    """Schema for the RCAAnalystAgent's structured output."""
    root_cause: str = Field(description="A concise string explaining the root cause of the incident")
    attack_phases: List[str] = Field(description="A sequential list of steps or phases the attacker took")
    blast_radius: int = Field(description="The estimated number of impacted entities based on the evidence")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0 in this analysis")


class ResponseOutput(BaseModel):
    """Schema for the ResponsePlannerAgent's structured output."""
    actions_recommended: List[str] = Field(description="List of exact actionable steps extracted from UNDER the 'Containment Actions' and 'Eradication & Recovery' headers. You MUST extract the ENTIRE sentence for each step, not just the bolded titles.")
    critical_actions: int = Field(description="The exact number of actions extracted that are marked as '(Priority: Critical)' in the playbook.")
    summary: str = Field(description="A brief summary explaining why these specific playbook steps apply to this incident.")
