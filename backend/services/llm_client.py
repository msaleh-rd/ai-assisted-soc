from typing import List, Dict, Any, Literal
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
import os

# Base URL for local LM Studio
LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://127.0.0.1:1234/v1")
# Model identifier can be anything or specifically match the loaded model
DEFAULT_MODEL = os.getenv("LLM_MODEL", "qwen2.5-7b-instruct")

# Role-specific model overrides
MODEL_ROUTING = {
    "triage": os.getenv("LLM_TRIAGE_MODEL", DEFAULT_MODEL),
    "rca": os.getenv("LLM_RCA_MODEL", DEFAULT_MODEL),
    "response": os.getenv("LLM_RESPONSE_MODEL", DEFAULT_MODEL),
    "planner": os.getenv("LLM_PLANNER_MODEL", DEFAULT_MODEL),
}

def get_llm(role: str = "default"):
    """Returns a configured LangChain ChatOpenAI instance pointing to local LM Studio.
    
    Args:
        role: The role of the agent ('triage', 'rca', 'response', etc.) for model routing.
    """
    model_name = MODEL_ROUTING.get(role, DEFAULT_MODEL)
    
    # Fast models for triage, powerful models for RCA/response
    max_tokens = 512 if role == "triage" else 1024
    
    return ChatOpenAI(
        base_url=LM_STUDIO_URL,
        api_key="lm-studio",  # API key is ignored by LM Studio but required by the client
        model=model_name,
        temperature=0.1,  # Low temperature for deterministic security analysis
        max_tokens=max_tokens
    )


# ---------------------------------------------------------------------------
# Structured Output Schemas
# ---------------------------------------------------------------------------

class Entity(BaseModel):
    type: str = Field(description="Type of entity, e.g., 'user', 'host', 'ip', 'file', 'process', 'domain'")
    id: str = Field(description="The unique identifier or value of the entity")


class PlannerTask(BaseModel):
    """A single task in the AI planner's output."""
    id: str = Field(description="Unique task ID, e.g. 'task-triage', 'task-evidence'")
    agent_name: str = Field(description="The exact agent name from the registry, e.g. 'triage_agent'")
    description: str = Field(description="Brief description of what this agent will do for this alert")


class PlannerOutput(BaseModel):
    """Structured output from the AI investigation planner."""
    phases: List[List[PlannerTask]] = Field(description="Ordered list of phases. Each phase is a list of tasks that can run in parallel.")
    reasoning: str = Field(description="Explanation of why this plan was chosen for the given alert")

class TriageOutput(BaseModel):
    """Schema for the TriageAgent's structured output."""
    severity: str = Field(description="Severity level: 'Critical', 'High', 'Medium', 'Low'")
    classification: str = Field(description="Classification of the alert, e.g., 'malware_execution', 'lateral_movement'")
    tactic: str = Field(description="MITRE ATT&CK tactic, if applicable")
    technique: str = Field(description="MITRE ATT&CK technique or technique ID, if applicable")
    entities_identified: List[Entity] = Field(description="List of entities extracted from the raw alert")
    requires_immediate_action: bool = Field(description="True if the alert severity is High or Critical")
    initial_assessment: str = Field(description="A 1-2 sentence human-readable summary of the alert")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0 reflecting certainty in this triage assessment", ge=0.0, le=1.0)


class InterAgentMessage(BaseModel):
    target_agent: Literal["evidence_agent", "rca_agent", "response_agent", "triage_agent", "*"] = Field(description="The specific agent you are messaging.")
    msg_type: Literal["REQUEST_EVIDENCE", "LOW_CONFIDENCE", "CHALLENGE", "FYI"] = Field(description="The intent of the message.")
    payload: Dict[str, str] = Field(default_factory=dict, description="Key-value dictionary of parameters or details to pass.")
    reason: str = Field(description="Why you are sending this message.")

class RCAOutput(BaseModel):
    """Schema for the RCAAgent's structured output."""
    chain_of_thought_verification: str = Field(description="Step-by-step verification of how the evidence supports the attack phases. Point out any gaps, contradictions, or missing evidence.")
    root_cause: str = Field(description="One sentence summary of the root cause")
    attack_phases: List[str] = Field(description="Sequential list of attack phases reconstructed from evidence")
    blast_radius: int = Field(description="The estimated number of impacted entities based on the evidence")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0 in this analysis")
    agent_messages: List[InterAgentMessage] = Field(default_factory=list, description="Optional. Send messages to other agents to request missing evidence.")


class ActionItem(BaseModel):
    action_type: str = Field(description="Must be exactly one of: isolate_host, reset_credentials, block_ip, block_domain, kill_process, revoke_mfa, disable_account, patch_system, enable_mfa, update_firewall")
    target: str = Field(description="The specific IP, hostname, or username to target for this action, extracted from the entities")
    description: str = Field(description="The full verbatim description of the action from the playbook")
    priority: str = Field(description="The priority of the action, usually 'Critical', 'High', 'Medium', or 'Low'")

class ResponseOutput(BaseModel):
    """Schema for the ResponsePlannerAgent's structured output."""
    actions_recommended: List[ActionItem] = Field(description="List of structured response actions to take")
    critical_actions: int = Field(description="The exact number of actions extracted that are marked as '(Priority: Critical)' in the playbook.")
    summary: str = Field(description="A brief summary explaining why these specific playbook steps apply to this incident.")
    agent_messages: List[InterAgentMessage] = Field(default_factory=list, description="Optional. Send messages to challenge low confidence RCA findings.")

class EvidenceSkillDeployment(BaseModel):
    skill_name: str = Field(description="The exact name of the evidence skill to deploy (e.g., 'edr-process-tree', 'threat-intel-lookup', 'network-flow-analyzer', 'identity-ad-lookup', 'file-forensics', 'persistence-auditor')")
    target_entity: str = Field(description="The entity ID (host, user, ip, file, or hash) to run this skill on")
    reasoning: str = Field(description="Why this skill is relevant for this specific entity")

class AgenticEvidenceOutput(BaseModel):
    """Schema for LLM-driven evidence collection plan."""
    skills_to_deploy: List[EvidenceSkillDeployment] = Field(description="List of targeted evidence skills to execute for the investigation entities")
    collection_strategy: str = Field(description="Brief overview of the evidence collection strategy")

class AgenticCompressionOutput(BaseModel):
    """Schema for LLM-driven compression and correlation strategy."""
    selected_skills: List[str] = Field(description="List of compression skills to apply (e.g. 'duplicate-rollup', 'temporal-clustering', 'behavioral-anomaly-filter', 'entity-graph-reduction', 'semantic-summarizer')")
    window_minutes: int = Field(default=30, description="Time window in minutes for temporal grouping")
    strategy_reasoning: str = Field(description="Why this noise reduction strategy fits this alert volume and type")

def verify_entities(entities: List[Entity], context_text: str) -> List[Entity]:
    """
    Hallucination Detection:
    Validates that the IDs of the extracted entities actually exist in the source context.
    Returns only the entities that can be grounded in the context.
    """
    valid_entities = []
    # Make context search case-insensitive to be safe
    context_lower = str(context_text).lower()
    
    for entity in entities:
        # Check if the entity ID string exists in the raw context
        if str(entity.id).lower() in context_lower:
            valid_entities.append(entity)
        else:
            import logging
            logging.getLogger("llm_client").warning(
                f"Hallucination detected: Entity {entity.id} ({entity.type}) not found in context. Dropping."
            )
            
    return valid_entities
