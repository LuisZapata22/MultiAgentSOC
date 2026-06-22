import asyncio
from typing import Optional, Dict, Any
from .models import OrchestratorState, TraceRecord
from .trace import TraceLogger
from .agents.telemetry_agent import TelemetryAgent

class OrchestratorStateMachine:
    def __init__(self, db_path: str = "trace.db"):
        self.state = OrchestratorState.UPLOADED
        self.logger = TraceLogger(db_path)
        self.telemetry_agent = TelemetryAgent()
        
    async def process_telemetry(self, file_path: str, source_type: str = "zeek"):
        """
        Starts the workflow by transitioning from UPLOADED to NORMALIZING
        and executing the Telemetry Agent.
        """
        if self.state != OrchestratorState.UPLOADED:
            raise RuntimeError(f"Cannot process telemetry from state {self.state}")
            
        print(f"[*] State transition: {self.state} -> {OrchestratorState.NORMALIZING}")
        self.state = OrchestratorState.NORMALIZING
        
        print(f"[*] Invoking Telemetry Agent on {file_path}...")
        try:
            # The agent acts as an MCP client and calls the Evidence Server
            result = await self.telemetry_agent.normalize(file_path, source_type)
            
            # Transition depends on result
            next_state = OrchestratorState.DETECTING if result["status"] == "success" else OrchestratorState.BLOCKED
            
            # Record trace
            trace = TraceRecord(
                sender="Host",
                receiver="TelemetryAgent",
                task="normalize_telemetry",
                evidence_used=[file_path],
                result=result,
                confidence=1.0, # Deterministic parser
                next_action=next_state,
                llm_provider=None, # No LLM in this stage
                fallback_triggered=False
            )
            self.logger.log(trace)
            
            print(f"[*] Agent finished. Trace recorded. Next state: {next_state}")
            self.state = next_state
            
        except Exception as e:
            print(f"[!] Error during normalization: {e}")
            self.state = OrchestratorState.BLOCKED
            
            trace = TraceRecord(
                sender="Host",
                receiver="TelemetryAgent",
                task="normalize_telemetry",
                evidence_used=[file_path],
                result={"status": "error", "message": str(e)},
                confidence=0.0,
                next_action=OrchestratorState.BLOCKED
            )
            self.logger.log(trace)
