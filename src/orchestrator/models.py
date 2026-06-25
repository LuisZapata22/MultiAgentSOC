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
    AWAITING_INPUT = "AWAITING_INPUT"
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


# --- Elicitation Models ---

class ElicitationFieldType(str, Enum):
    TEXT = "text"
    TEXTAREA = "textarea"
    SELECT = "select"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    MULTI_SELECT = "multi-select"


class ElicitationField(BaseModel):
    """A single field in an elicitation form."""
    name: str = Field(..., description="Machine-readable field identifier")
    field_type: ElicitationFieldType = Field(..., description="The input type for this field")
    label: str = Field(..., description="Human-readable label displayed to the analyst")
    options: Optional[List[str]] = Field(None, description="Options for select/radio/multi-select fields")
    required: bool = Field(True, description="Whether this field is required")
    default: Optional[str] = Field(None, description="Default value for the field")


class ElicitationRequest(BaseModel):
    """
    A request from an agent for human input.
    Contains the form schema and contextual evidence for the analyst.
    """
    id: str = Field(..., description="Unique identifier for this elicitation request")
    agent: str = Field(..., description="The agent requesting input (detection, validation, reporting)")
    stage: str = Field(..., description="The OrchestratorState where the pause occurred")
    title: str = Field(..., description="Title of the elicitation request")
    description: str = Field(..., description="Explanation of why human input is needed")
    context: Dict[str, Any] = Field(default_factory=dict, description="Evidence/findings relevant to the question")
    fields: List[ElicitationField] = Field(..., description="List of form fields to render")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp"
    )


class ElicitationResponse(BaseModel):
    """
    The analyst's response to an elicitation request.
    """
    request_id: str = Field(..., description="The ID of the elicitation request being responded to")
    responses: Dict[str, Any] = Field(..., description="Map of field name to analyst's answer")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp"
    )

