import asyncio
from typing import Optional, Dict, Any
from .models import OrchestratorState, TraceRecord
from .trace import TraceLogger
from .agents.telemetry_agent import TelemetryAgent
from .agents.detection_agent import DetectionAgent
from .agents.port_analyzer_agent import PortAnalyzerAgent

class OrchestratorStateMachine:
    def __init__(self, db_path: str = "trace.db"):
        self.state = OrchestratorState.UPLOADED
        self.logger = TraceLogger(db_path)
        self.telemetry_agent = TelemetryAgent()
        self.detection_agent = DetectionAgent()
        self.port_analyzer_agent = PortAnalyzerAgent()
        self.current_findings = []
        
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
            result = await self.telemetry_agent.normalize(file_path, source_type)
            
            next_state = OrchestratorState.DETECTING if result["status"] == "success" else OrchestratorState.BLOCKED
            
            trace = TraceRecord(
                sender="Host",
                receiver="TelemetryAgent",
                task="normalize_telemetry",
                evidence_used=[file_path],
                result=result,
                confidence=1.0,
                next_action=next_state,
                llm_provider=None,
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

    async def run_detection(self):
        """
        Executes the detection agent.
        """
        if self.state != OrchestratorState.DETECTING:
            raise RuntimeError(f"Cannot run detection from state {self.state}")
            
        print(f"[*] State transition: {self.state} -> processing detection")
        
        try:
            result = await self.detection_agent.run_detection()
            
            requires_port_analysis = result.get("requires_port_analysis", False)
            next_state = OrchestratorState.PORT_ANALYSIS if requires_port_analysis else OrchestratorState.MITRE_MAPPING
            
            findings = result.get("findings", [])
            self.current_findings.extend(findings)
            
            evidence_used = []
            for f in findings:
                evidence_used.extend(f.get("evidence_refs", []))
            
            provider_info = result.pop("provider_info", {})
            
            trace = TraceRecord(
                sender="DetectionAgent",
                receiver="PortAnalyzerAgent" if requires_port_analysis else "MitreAgent",
                task="detect_anomalies",
                evidence_used=list(set(evidence_used)),
                result=result,
                confidence=0.8,
                next_action=next_state,
                llm_provider=provider_info.get("provider"),
                fallback_triggered=provider_info.get("fallback_triggered", False)
            )
            self.logger.log(trace)
            
            print(f"[*] Agent finished. Trace recorded. Next state: {next_state}")
            self.state = next_state
            
        except Exception as e:
            print(f"[!] Error during detection: {e}")
            self.state = OrchestratorState.BLOCKED
            
            trace = TraceRecord(
                sender="DetectionAgent",
                receiver="Host",
                task="detect_anomalies",
                evidence_used=[],
                result={"status": "error", "message": str(e)},
                confidence=0.0,
                next_action=OrchestratorState.BLOCKED
            )
            self.logger.log(trace)

    async def run_port_analysis(self):
        """
        Executes the port analyzer agent if requested by Detection.
        """
        if self.state != OrchestratorState.PORT_ANALYSIS:
            raise RuntimeError(f"Cannot run port analysis from state {self.state}")
            
        print(f"[*] State transition: {self.state} -> processing port analysis")
        
        try:
            result = await self.port_analyzer_agent.run_port_analysis(self.current_findings)
            
            next_state = OrchestratorState.MITRE_MAPPING
            
            findings = result.get("findings", [])
            self.current_findings.extend(findings)
            
            evidence_used = []
            for f in findings:
                evidence_used.extend(f.get("evidence_refs", []))
            
            provider_info = result.pop("provider_info", {})
            
            trace = TraceRecord(
                sender="PortAnalyzerAgent",
                receiver="MitreAgent",
                task="analyze_port_behavior",
                evidence_used=list(set(evidence_used)),
                result=result,
                confidence=0.8,
                next_action=next_state,
                llm_provider=provider_info.get("provider"),
                fallback_triggered=provider_info.get("fallback_triggered", False)
            )
            self.logger.log(trace)
            
            print(f"[*] Agent finished. Trace recorded. Next state: {next_state}")
            self.state = next_state
            
        except Exception as e:
            print(f"[!] Error during port analysis: {e}")
            self.state = OrchestratorState.BLOCKED
            
            trace = TraceRecord(
                sender="PortAnalyzerAgent",
                receiver="Host",
                task="analyze_port_behavior",
                evidence_used=[],
                result={"status": "error", "message": str(e)},
                confidence=0.0,
                next_action=OrchestratorState.BLOCKED
            )
            self.logger.log(trace)
