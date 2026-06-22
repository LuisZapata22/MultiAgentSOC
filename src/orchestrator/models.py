from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

class OrchestratorState(str, Enum):
    UPLOADED = "UPLOADED"
    NORMALIZING = "NORMALIZING"
    DETECTING = "DETECTING"
    PORT_ANALYSIS = "PORT_ANALYSIS"
    MITRE_MAPPING = "MITRE_MAPPING"
    VALIDATING = "VALIDATING"
    REPORTING = "REPORTING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"

class TraceRecord(BaseModel):
    """
    Structured trace record for every agent-to-agent exchange.
    """
    sender: str = Field(..., description="The agent or component sending the action")
    receiver: str = Field(..., description="The agent or component receiving the action")
    task: str = Field(..., description="Description of the task performed")
    evidence_used: List[str] = Field(default_factory=list, description="List of evidence/event IDs or references used")
    result: Dict[str, Any] = Field(default_factory=dict, description="Structured result payload")
    confidence: float = Field(0.0, description="Confidence score (0.0 to 1.0)")
    next_action: OrchestratorState = Field(..., description="The state transition resulting from this action")
    llm_provider: Optional[str] = Field(None, description="The LLM provider used (e.g., gemini, groq, claude)")
    fallback_triggered: bool = Field(False, description="Whether an LLM fallback was triggered")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp"
    )
