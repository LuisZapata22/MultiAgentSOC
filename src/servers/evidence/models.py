from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class NormalizedEvent(BaseModel):
    """
    Standard schema for normalized network telemetry events.
    """
    timestamp: float = Field(..., description="Timestamp of the event in epoch seconds")
    source_ip: str = Field(..., description="Source IP address")
    source_port: int = Field(..., description="Source port")
    destination_ip: str = Field(..., description="Destination IP address")
    destination_port: int = Field(..., description="Destination port")
    protocol: str = Field(..., description="Network protocol (e.g., tcp, udp, icmp)")
    service: Optional[str] = Field(None, description="Identified application service (e.g., http, dns, ssl)")
    duration: Optional[float] = Field(None, description="Duration of the connection in seconds")
    bytes_sent: Optional[int] = Field(None, description="Bytes sent from source to destination")
    bytes_received: Optional[int] = Field(None, description="Bytes received from destination to source")
    connection_state: Optional[str] = Field(None, description="Connection state (e.g., Zeek conn_state like SF, S0, REJ)")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="The original raw event data")

