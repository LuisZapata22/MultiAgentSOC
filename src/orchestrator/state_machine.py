import asyncio
from typing import Optional, Dict, Any
from .models import OrchestratorState, TraceRecord
from .trace import TraceLogger
from .agents.telemetry_agent import TelemetryAgent
from .agents.detection_agent import DetectionAgent
from .agents.port_analyzer_agent import PortAnalyzerAgent
from .agents.mitre_agent import MitreAgent
from .agents.validation_agent import ValidationAgent
from .agents.reporting_agent import ReportingAgent

class OrchestratorStateMachine:
    def __init__(self, db_path: str = "trace.db"):
        self.state = OrchestratorState.UPLOADED
        self.logger = TraceLogger(db_path)
        self.telemetry_agent = TelemetryAgent()
        self.detection_agent = DetectionAgent()
        self.port_analyzer_agent = PortAnalyzerAgent()
        self.mitre_agent = MitreAgent()
        self.validation_agent = ValidationAgent()
        self.reporting_agent = ReportingAgent()
        self.current_findings = []
        self.validation_result = {}
        
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

    async def run_mitre_mapping(self):
        """
        Executes the MITRE mapping agent to assign tactics/techniques.
        """
        if self.state != OrchestratorState.MITRE_MAPPING:
            raise RuntimeError(f"Cannot run MITRE mapping from state {self.state}")
            
        print(f"[*] State transition: {self.state} -> processing MITRE mapping")
        
        try:
            result = await self.mitre_agent.run_mitre_mapping(self.current_findings)
            
            next_state = OrchestratorState.VALIDATING
            
            # Since MITRE mappings aren't new findings but enrichments,
            # we just append them to the cumulative state or store them separately.
            self.current_findings.append({"mitre_mappings": result.get("mitre_mappings", [])})
            
            # Evidence used is implicitly all the findings passed in
            evidence_used = ["all_previous_findings"]
            
            provider_info = result.pop("provider_info", {})
            
            trace = TraceRecord(
                sender="MitreAgent",
                receiver="ValidationAgent",
                task="map_to_mitre",
                evidence_used=evidence_used,
                result=result,
                confidence=0.9, # Taxonomy lookup is usually high confidence
                next_action=next_state,
                llm_provider=provider_info.get("provider"),
                fallback_triggered=provider_info.get("fallback_triggered", False)
            )
            self.logger.log(trace)
            
            print(f"[*] Agent finished. Trace recorded. Next state: {next_state}")
            self.state = next_state
            
        except Exception as e:
            print(f"[!] Error during MITRE mapping: {e}")
            self.state = OrchestratorState.BLOCKED
            
            trace = TraceRecord(
                sender="MitreAgent",
                receiver="Host",
                task="map_to_mitre",
                evidence_used=[],
                result={"status": "error", "message": str(e)},
                confidence=0.0,
                next_action=OrchestratorState.BLOCKED
            )
            self.logger.log(trace)

    async def run_validation(self):
        """
        Executes the Validation Agent: deterministic rule checks + LLM plain-language summary.
        Transitions from VALIDATING -> REPORTING.
        """
        if self.state != OrchestratorState.VALIDATING:
            raise RuntimeError(f"Cannot run validation from state {self.state}")

        print(f"[*] State transition: {self.state} -> processing validation")

        try:
            result = await self.validation_agent.run_validation(self.current_findings)

            next_state = OrchestratorState.REPORTING

            # Store the full validation output for the Reporting stage
            self.validation_result = result

            provider_info = result.pop("provider_info", {})
            det_report = result.get("deterministic_report", {})
            summary = det_report.get("summary", {})

            trace = TraceRecord(
                sender="ValidationAgent",
                receiver="ReportingAgent",
                task="validate_findings",
                evidence_used=["all_previous_findings"],
                result={
                    "status": result["status"],
                    "summary": summary,
                    "llm_summary": result.get("llm_summary", {})
                },
                confidence=1.0,  # Deterministic layer is always 1.0
                next_action=next_state,
                llm_provider=provider_info.get("provider"),
                fallback_triggered=provider_info.get("fallback_triggered", False)
            )
            self.logger.log(trace)

            print(f"[*] Agent finished. Trace recorded. Next state: {next_state}")
            self.state = next_state

        except Exception as e:
            print(f"[!] Error during validation: {e}")
            self.state = OrchestratorState.BLOCKED

            trace = TraceRecord(
                sender="ValidationAgent",
                receiver="Host",
                task="validate_findings",
                evidence_used=[],
                result={"status": "error", "message": str(e)},
                confidence=0.0,
                next_action=OrchestratorState.BLOCKED
            )
            self.logger.log(trace)

    async def run_reporting(self):
        """
        Executes the Reporting Agent — calls Claude for the final report
        and persists it via the Reporting MCP Server.
        Transitions from REPORTING -> COMPLETE.
        """
        if self.state != OrchestratorState.REPORTING:
            raise RuntimeError(f"Cannot run reporting from state {self.state}")

        print(f"[*] State transition: {self.state} -> generating final report")

        try:
            result = await self.reporting_agent.run_reporting(
                validation_result=self.validation_result,
                all_findings=self.current_findings
            )

            next_state = OrchestratorState.COMPLETE
            provider_info = result.pop("provider_info", {})

            trace = TraceRecord(
                sender="ReportingAgent",
                receiver="Host",
                task="generate_report",
                evidence_used=["all_previous_findings"],
                result={
                    "status": result["status"],
                    "saved_path": result.get("saved_path"),
                    "risk_level": result.get("report", {}).get("risk_level"),
                },
                confidence=1.0,
                next_action=next_state,
                llm_provider=provider_info.get("provider"),
                fallback_triggered=provider_info.get("fallback_triggered", False)
            )
            self.logger.log(trace)

            # Store for external access (e.g. dashboard API)
            self.final_report = result.get("report", {})
            self.report_path = result.get("saved_path")

            print(f"[*] Report generation complete. Saved to: {self.report_path}")
            self.state = next_state

        except Exception as e:
            print(f"[!] Error during reporting: {e}")
            self.state = OrchestratorState.BLOCKED

            trace = TraceRecord(
                sender="ReportingAgent",
                receiver="Host",
                task="generate_report",
                evidence_used=[],
                result={"status": "error", "message": str(e)},
                confidence=0.0,
                next_action=OrchestratorState.BLOCKED
            )
            self.logger.log(trace)
