import os
import json
from typing import Dict, Any, List
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter

class ReportingAgent:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.llm_router = LLMRouter()

    async def run_reporting(self, validation_result: Dict[str, Any], all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calls Claude (via LLMRouter) to produce the final formal JSON report,
        then uses the Reporting Server to persist it to disk.
        """
        reporting_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.reporting.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )

        async with AsyncExitStack() as stack:
            rep_read, rep_write = await stack.enter_async_context(stdio_client(reporting_params))
            rep_session = await stack.enter_async_context(ClientSession(rep_read, rep_write))
            await rep_session.initialize()

            # Extract the relevant parts for the prompt
            det_report = validation_result.get("deterministic_report", {})
            llm_summary = validation_result.get("llm_summary", {})

            # Pull out MITRE mappings from the findings list
            mitre_mappings = []
            for f in all_findings:
                if "mitre_mappings" in f:
                    mitre_mappings.extend(f["mitre_mappings"])

            validation_report_json = json.dumps(det_report, indent=2)
            mitre_mappings_json = json.dumps(mitre_mappings, indent=2)
            llm_summary_json = json.dumps(llm_summary, indent=2)

            # Fetch the report generation prompt from the Reporting Server
            prompt_result = await rep_session.get_prompt(
                "report_generation_template",
                arguments={
                    "validation_report_json": validation_report_json,
                    "mitre_mappings_json": mitre_mappings_json,
                    "llm_summary_json": llm_summary_json,
                }
            )
            prompt_text = "\n".join([
                msg.content.text for msg in prompt_result.messages
                if msg.content.type == "text"
            ])

            # Call Claude for report generation
            print("[*] Calling Claude for final report generation...")
            llm_response = self.llm_router.call(stage="report", prompt=prompt_text)

            raw_text = llm_response.get("result", "{}")
            report_obj = self._extract_json(raw_text)

            # If Claude is unavailable, build a minimal structural report from deterministic data
            if not report_obj or "findings" not in report_obj:
                print("[!] Claude report generation failed or returned empty. Building fallback report.")
                report_obj = self._build_fallback_report(det_report, mitre_mappings, llm_summary)

            # Save the report to disk via the MCP tool
            save_result_raw = await rep_session.call_tool(
                "save_report",
                arguments={"report_json": json.dumps(report_obj)}
            )
            save_result = json.loads(save_result_raw.content[0].text)

            print(f"[*] Report saved: {save_result.get('path', 'unknown')}")

            return {
                "status": "success",
                "report": report_obj,
                "saved_path": save_result.get("path"),
                "provider_info": {
                    "provider": llm_response.get("provider", "none"),
                    "fallback_triggered": llm_response.get("fallback_triggered", False)
                }
            }

    def _build_fallback_report(
        self,
        det_report: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]],
        llm_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Builds a minimal structural report when Claude is unavailable."""
        import uuid
        from datetime import datetime, timezone

        validated = det_report.get("validated_findings", [])
        summary = det_report.get("summary", {})
        risk_level = "CRITICAL" if summary.get("critical", 0) > 0 else \
                     "HIGH" if summary.get("confirmed", 0) > 0 else "MEDIUM"

        findings = []
        for i, v in enumerate(validated):
            tech_id = v.get("mitre_technique_id", "")
            # Find the corresponding MITRE mapping for tactic
            tactic = ""
            for m in mitre_mappings:
                if m.get("mitre_technique_id") == tech_id:
                    tactic = m.get("mitre_tactic", "")
                    break

            findings.append({
                "id": str(i + 1),
                "title": v.get("finding", "Unknown Finding")[:80],
                "description": v.get("finding", ""),
                "mitre_technique_id": tech_id,
                "mitre_tactic": tactic,
                "severity": "high" if v["status"] in ("CRITICAL", "CONFIRMED") else "medium",
                "status": v["status"],
                "recommended_action": v.get("reason", "Review with a human analyst.")
            })

        return {
            "report_id": str(uuid.uuid4())[:8],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": llm_summary.get("risk_summary", "Automated analysis complete. Human review required."),
            "risk_level": risk_level,
            "findings": findings,
            "recommended_next_steps": [llm_summary.get("recommended_action", "Escalate to Tier 2 analyst.")],
            "analyst_notes": "This report was generated without Claude AI assistance. LLM summary fields may be incomplete."
        }

    def _extract_json(self, text: str) -> Dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except Exception as e:
            print(f"[!] Error parsing Claude JSON report: {e}")
            return {}
