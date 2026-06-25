from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class TelemetryRecord(BaseModel):
    """
    Standardized schema for incoming telemetry events passed into heuristic rules.
    """
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    dns_query: Optional[str] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    state: Optional[str] = None
    bytes_sent: Optional[int] = 0
    bytes_received: Optional[int] = 0
    raw_data: Any = Field(default_factory=dict)

class Finding(BaseModel):
    """
    Structured output from a detection heuristic or LLM agent.
    """
    title: str
    description: str
    severity: Severity
    source_ip: str
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    detection_type: str
    timestamp: datetime
    evidence: Dict[str, Any] = Field(default_factory=dict)
    raw_data: Any = Field(default_factory=dict)
