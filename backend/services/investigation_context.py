import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
import copy

@dataclass
class AgentMessage:
    """A structured message emitted by an agent during the investigation."""
    msg_type: str          # e.g., REQUEST_EVIDENCE, LOW_CONFIDENCE, NEW_ENTITY, CHALLENGE
    source_agent: str
    target_agent: str      # agent name or "*" for broadcast
    payload: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    resolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentMessage":
        return cls(**data)


@dataclass
class InvestigationContext:
    """
    Shared blackboard containing all state for an investigation.
    Agents read from and write to this context instead of passing dicts linearly.
    """
    alert_data: Dict[str, Any] = field(default_factory=dict)
    use_ai_planner: bool = False
    
    # Phase 1: Triage outputs
    entities: List[Dict[str, Any]] = field(default_factory=list)
    classification: str = "unknown"
    severity: str = "unknown"
    
    # Phase 2: Evidence outputs
    entity_graph: Dict[str, Any] = field(default_factory=dict)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    raw_events: List[Dict[str, Any]] = field(default_factory=list)
    
    # Phase 3: Compression outputs
    compressed_events: Dict[str, Any] = field(default_factory=dict)
    
    # Phase 4: RCA outputs
    rca_findings: Dict[str, Any] = field(default_factory=dict)
    causal_candidates: List[Dict[str, Any]] = field(default_factory=list)
    
    # Adaptive Loop / Communication state
    messages: List[AgentMessage] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 3
    confidence_history: List[float] = field(default_factory=list)

    def post_message(self, msg_type: str, source: str, target: str, payload: Dict[str, Any]) -> None:
        """Post a new message to the blackboard."""
        msg = AgentMessage(
            msg_type=msg_type,
            source_agent=source,
            target_agent=target,
            payload=payload
        )
        self.messages.append(msg)

    def get_pending_messages(self, target_agent: str) -> List[AgentMessage]:
        """Get unresolved messages targeting a specific agent or broadcast."""
        return [
            m for m in self.messages 
            if not m.resolved and (m.target_agent == target_agent or m.target_agent == "*")
        ]
        
    def resolve_messages(self, messages: List[AgentMessage]) -> None:
        """Mark specific messages as resolved."""
        for msg in messages:
            msg.resolved = True

    def needs_reinvestigation(self) -> bool:
        """
        Determine if we should loop back to evidence collection.
        Triggers if RCA confidence is < 0.7 OR if there are pending REQUEST_EVIDENCE messages,
        AND we haven't hit the iteration cap.
        """
        if self.iteration >= self.max_iterations:
            return False
            
        current_confidence = self.rca_findings.get("confidence_score", 0.0)
        
        has_pending_requests = any(
            m.msg_type == "REQUEST_EVIDENCE" and not m.resolved 
            for m in self.messages
        )
        
        # We also trigger re-investigation if confidence is simply too low
        # and we haven't given up yet.
        is_low_confidence = current_confidence > 0 and current_confidence < 0.7
        
        return has_pending_requests or is_low_confidence

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for Temporal payload."""
        data = asdict(self)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationContext":
        """Deserialize from Temporal payload."""
        if not data:
            return cls()
            
        # Handle nested objects that need specific deserialization
        messages_data = data.pop("messages", [])
        messages = [AgentMessage.from_dict(m) for m in messages_data]
        
        return cls(messages=messages, **data)
