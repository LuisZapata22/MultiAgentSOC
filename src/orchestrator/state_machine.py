import asyncio
from typing import Optional, Dict, Any
from .models import OrchestratorState, TraceRecord, ElicitationRequest
from .trace import TraceLogger
from .elicitation import ElicitationManager
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
        self.elicitation_mgr = ElicitationManager(db_path)
        self.telemetry_agent = TelemetryAgent()
        self.detection_agent = DetectionAgent()
        self.port_analyzer_agent = PortAnalyzerAgent()
        self.mitre_agent = MitreAgent()
        self.validation_agent = ValidationAgent()
        self.reporting_agent = ReportingAgent()
        self.current_findings = []
        self.validation_result = {}
        self.final_report = {}
        self.report_path = None
        # Track which stage we were in before an elicitation pause
        self._pre_elicitation_state: Optional[OrchestratorState] = None

    async def _handle_elicitation(self, result: Dict[str, Any], agent_name: str) -> Optional[Dict[str, Any]]:
        """
        Checks if an agent result contains an elicitation request.
        If yes, pauses the pipeline and waits for the analyst's response.
        Returns the analyst's responses dict, or None if no elicitation was needed or timeout occurred.
        """
        if "elicitation_request" not in result:
            return None

        req_data = result["elicitation_request"]
        req = ElicitationRequest(**req_data)

        # Save state before pausing
        self._pre_elicitation_state = self.state
        self.state = OrchestratorState.AWAITING_INPUT

        # Log the elicitation trace
        trace = TraceRecord(
            sender=agent_name,
            receiver="Analyst",
            task=f"elicitation_request: {req.title}",
            evidence_used=[],
            result={"elicitation_id": req.id, "title": req.title, "fields_count": len(req.fields)},
            confidence=0.0,
            next_action=OrchestratorState.AWAITING_INPUT,
            llm_provider=None,
            fallback_triggered=False
        )
        self.logger.log(trace)

        # Block until analyst responds or timeout
        response = await self.elicitation_mgr.request_input(req)

        if response is None:
            # Timeout — kill the pipeline
            self.state = OrchestratorState.BLOCKED
            trace = TraceRecord(
                sender="Analyst",
                receiver=agent_name,
                task="elicitation_timeout",
                evidence_used=[req.id],
                result={"status": "timeout", "message": "Analyst did not respond within 5 minutes."},
                confidence=0.0,
                next_action=OrchestratorState.BLOCKED,
                llm_provider=None,
                fallback_triggered=False
            )
            self.logger.log(trace)
            return None

        # Log the analyst's response
        trace = TraceRecord(
            sender="Analyst",
            receiver=agent_name,
            task=f"elicitation_response: {req.title}",
            evidence_used=[req.id],
            result={"responses": response.responses},
            confidence=1.0,
            next_action=self._pre_elicitation_state,
            llm_provider=None,
            fallback_triggered=False
        )
        self.logger.log(trace)

        # Restore pre-elicitation state
        self.state = self._pre_elicitation_state
        self._pre_elicitation_state = None

        return response.responses

    async def process_telemetry(self, file_path: str, source_type: str = "zeek"):
        if self.state != OrchestratorState.UPLOADED:
            raise RuntimeError(f"Cannot process telemetry from state {self.state}")
        self.state = OrchestratorState.NORMALIZING
        try:
            result = await self.telemetry_agent.normalize(file_path, source_type)
            next_state = OrchestratorState.DETECTING if result["status"] == "success" else OrchestratorState.BLOCKED
            trace = TraceRecord(sender="Host", receiver="TelemetryAgent", task="normalize_telemetry", evidence_used=[file_path], result=result, confidence=1.0, next_action=next_state, llm_provider=None, fallback_triggered=False)
            self.logger.log(trace)
            self.state = next_state
        except Exception as e:
            self.state = OrchestratorState.BLOCKED
            trace = TraceRecord(sender="Host", receiver="TelemetryAgent", task="normalize_telemetry", evidence_used=[file_path], result={"status": "error", "message": str(e)}, confidence=0.0, next_action=OrchestratorState.BLOCKED)
            self.logger.log(trace)

    async def run_detection(self):
        if self.state != OrchestratorState.DETECTING:
            raise RuntimeError(f"Cannot run detection from state {self.state}")
        try:
            result = await self.detection_agent.run_detection()

            # Check for elicitation request
            user_context = await self._handle_elicitation(result, "DetectionAgent")
            if self.state == OrchestratorState.BLOCKED:
                return  # Timeout killed the pipeline

            if user_context is not None:
                # Re-run detection with analyst context
                result = await self.detection_agent.run_detection(user_context=user_context)

            requires_port_analysis = result.get("requires_port_analysis", False)
            next_state = OrchestratorState.PORT_ANALYSIS if requires_port_analysis else OrchestratorState.MITRE_MAPPING
            findings = result.get("findings", [])
            self.current_findings.extend(findings)
            provider_info = result.pop("provider_info", {})
            trace = TraceRecord(sender="DetectionAgent", receiver="PortAnalyzerAgent" if next_state == OrchestratorState.PORT_ANALYSIS else "MitreAgent", task="detect_anomalies", evidence_used=["all_events_fetched"], result={"status": result["status"], "findings_count": len(findings), "api_error": provider_info.get("error")}, confidence=0.8, next_action=next_state, llm_provider=provider_info.get("provider"), fallback_triggered=provider_info.get("fallback_triggered", False))
            self.logger.log(trace)
            self.state = next_state
        except Exception as e:
            self.state = OrchestratorState.BLOCKED
            trace = TraceRecord(sender="DetectionAgent", receiver="Host", task="detect_anomalies", evidence_used=[], result={"status": "error", "message": str(e)}, confidence=0.0, next_action=OrchestratorState.BLOCKED)
            self.logger.log(trace)

    async def run_port_analysis(self):
        if self.state != OrchestratorState.PORT_ANALYSIS:
            raise RuntimeError(f"Cannot run port analysis from state {self.state}")
        try:
            result = await self.port_analyzer_agent.run_port_analysis(self.current_findings)
            next_state = OrchestratorState.MITRE_MAPPING
            findings = result.get("findings", [])
            self.current_findings.extend(findings)
            provider_info = result.pop("provider_info", {})
            trace = TraceRecord(sender="PortAnalyzerAgent", receiver="MitreAgent", task="analyze_ports", evidence_used=["all_previous_findings"], result={"status": result["status"], "findings_count": len(findings), "api_error": provider_info.get("error")}, confidence=0.85, next_action=next_state, llm_provider=provider_info.get("provider"), fallback_triggered=provider_info.get("fallback_triggered", False))
            self.logger.log(trace)
            self.state = next_state
        except Exception as e:
            self.state = OrchestratorState.BLOCKED
            trace = TraceRecord(sender="PortAnalyzerAgent", receiver="Host", task="analyze_port_behavior", evidence_used=[], result={"status": "error", "message": str(e)}, confidence=0.0, next_action=OrchestratorState.BLOCKED)
            self.logger.log(trace)

    async def run_mitre_mapping(self):
        if self.state != OrchestratorState.MITRE_MAPPING:
            raise RuntimeError(f"Cannot run MITRE mapping from state {self.state}")
        try:
            result = await self.mitre_agent.run_mitre_mapping(self.current_findings)
            next_state = OrchestratorState.VALIDATING
            mapped_findings = result.get("mitre_mappings", [])
            self.current_findings.append({"mitre_mappings": mapped_findings})
            provider_info = result.pop("provider_info", {})
            trace = TraceRecord(sender="MitreAgent", receiver="ValidationAgent", task="map_to_mitre", evidence_used=["all_previous_findings"], result={"status": result["status"], "mapped_count": len(mapped_findings), "api_error": provider_info.get("error")}, confidence=0.9, next_action=next_state, llm_provider=provider_info.get("provider"), fallback_triggered=provider_info.get("fallback_triggered", False))
            self.logger.log(trace)
            self.state = next_state
        except Exception as e:
            self.state = OrchestratorState.BLOCKED
            trace = TraceRecord(sender="MitreAgent", receiver="Host", task="map_to_mitre", evidence_used=[], result={"status": "error", "message": str(e)}, confidence=0.0, next_action=OrchestratorState.BLOCKED)
            self.logger.log(trace)

    async def run_validation(self):
        if self.state != OrchestratorState.VALIDATING:
            raise RuntimeError(f"Cannot run validation from state {self.state}")
        try:
            result = await self.validation_agent.run_validation(self.current_findings)

            # Check for elicitation request
            user_context = await self._handle_elicitation(result, "ValidationAgent")
            if self.state == OrchestratorState.BLOCKED:
                return  # Timeout killed the pipeline

            if user_context is not None:
                # Re-run validation with analyst context
                result = await self.validation_agent.run_validation(self.current_findings, user_context=user_context)

            next_state = OrchestratorState.REPORTING
            self.validation_result = result
            provider_info = result.pop("provider_info", {})
            det_report = result.get("deterministic_report", {})
            summary = det_report.get("summary", {})
            trace = TraceRecord(sender="ValidationAgent", receiver="ReportingAgent", task="validate_findings", evidence_used=["all_previous_findings"], result={"status": result["status"], "summary": summary, "llm_summary": result.get("llm_summary", {}), "api_error": provider_info.get("error")}, confidence=1.0, next_action=next_state, llm_provider=provider_info.get("provider"), fallback_triggered=provider_info.get("fallback_triggered", False))
            self.logger.log(trace)
            self.state = next_state
        except Exception as e:
            self.state = OrchestratorState.BLOCKED
            trace = TraceRecord(sender="ValidationAgent", receiver="Host", task="validate_findings", evidence_used=[], result={"status": "error", "message": str(e)}, confidence=0.0, next_action=OrchestratorState.BLOCKED)
            self.logger.log(trace)

    async def run_reporting(self):
        if self.state != OrchestratorState.REPORTING:
            raise RuntimeError(f"Cannot run reporting from state {self.state}")
        try:
            # Get elicitation history for audit trail in the report
            elicitation_history = self.elicitation_mgr.get_history()

            result = await self.reporting_agent.run_reporting(
                validation_result=self.validation_result,
                all_findings=self.current_findings,
                elicitation_history=elicitation_history
            )

            # Check for elicitation request (report approval)
            user_context = await self._handle_elicitation(result, "ReportingAgent")
            if self.state == OrchestratorState.BLOCKED:
                return  # Timeout killed the pipeline

            if user_context is not None:
                # Re-run reporting with analyst preferences
                result = await self.reporting_agent.run_reporting(
                    validation_result=self.validation_result,
                    all_findings=self.current_findings,
                    elicitation_history=elicitation_history,
                    user_context=user_context
                )

            next_state = OrchestratorState.COMPLETE
            provider_info = result.pop("provider_info", {})
            trace = TraceRecord(sender="ReportingAgent", receiver="Host", task="generate_report", evidence_used=["all_previous_findings"], result={"status": result["status"], "saved_path": result.get("saved_path"), "risk_level": result.get("report", {}).get("risk_level"), "api_error": provider_info.get("error")}, confidence=1.0, next_action=next_state, llm_provider=provider_info.get("provider"), fallback_triggered=provider_info.get("fallback_triggered", False))
            self.logger.log(trace)
            self.final_report = result.get("report", {})
            self.report_path = result.get("saved_path")
            self.state = next_state
        except Exception as e:
            self.state = OrchestratorState.BLOCKED
            trace = TraceRecord(sender="ReportingAgent", receiver="Host", task="generate_report", evidence_used=[], result={"status": "error", "message": str(e)}, confidence=0.0, next_action=OrchestratorState.BLOCKED)
            self.logger.log(trace)
