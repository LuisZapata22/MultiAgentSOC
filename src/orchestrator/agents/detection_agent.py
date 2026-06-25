import os
import json
import asyncio
import uuid
from typing import Dict, Any, List, Optional
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter
from ..models import ElicitationFieldType


class DetectionAgent:
    # Configurable confidence threshold — below this, request analyst input
    CONFIDENCE_THRESHOLD = 0.6

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.llm_router = LLMRouter()

    async def run_detection(self, user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Fetches normalized events, gets the detection prompt, and routes to the LLM.
        If user_context is provided (from elicitation), it's injected into the LLM prompt.
        """
        evidence_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.evidence.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )
        detection_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.detection.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )

        async with AsyncExitStack() as stack:
            # Connect to Evidence Server
            ev_read, ev_write = await stack.enter_async_context(stdio_client(evidence_params))
            ev_session = await stack.enter_async_context(ClientSession(ev_read, ev_write))
            await ev_session.initialize()

            # Connect to Detection Server
            det_read, det_write = await stack.enter_async_context(stdio_client(detection_params))
            det_session = await stack.enter_async_context(ClientSession(det_read, det_write))
            await det_session.initialize()

            # 1. Fetch Events
            ev_result = await ev_session.call_tool("read_evidence", arguments={"limit": 1000, "offset": 0})
            events_json = ev_result.content[0].text if ev_result.content else "[]"

            # 2. Run Deterministic Heuristics First
            print("[*] Running Heuristic Detection Engine...")
            heuristic_result = await det_session.call_tool("run_heuristic_detections", arguments={"events_json": events_json})
            heuristic_findings_json = heuristic_result.content[0].text if heuristic_result.content else "[]"
            
            # Extract heuristic findings
            heuristic_findings = []
            try:
                heuristic_findings = json.loads(heuristic_findings_json)
            except Exception as e:
                print(f"[!] Error parsing heuristic findings: {e}")

            # 3. Check if elicitation is needed BEFORE calling LLM
            if user_context is None:
                elicitation = self._evaluate_elicitation_need(heuristic_findings, events_json)
                if elicitation is not None:
                    return elicitation

            # 4. Get Prompt Template
            prompt_result = await det_session.get_prompt(
                "detection_reasoning_template", 
                arguments={
                    "events_json": events_json, 
                    "heuristic_findings_json": heuristic_findings_json
                }
            )
            prompt_text = "\n".join([msg.content.text for msg in prompt_result.messages if msg.content.type == "text"])

            # Inject analyst context if provided
            if user_context:
                context_str = "\n".join([f"- {k}: {v}" for k, v in user_context.items()])
                prompt_text += f"\n\n=== ANALYST-PROVIDED CONTEXT ===\nThe analyst has provided the following additional context:\n{context_str}\nIncorporate this information into your analysis.\n"

            # 5. Call LLM Router for Enrichment
            print("[*] Calling LLM Router for Advanced Detection...")
            llm_response = self.llm_router.call(stage="detection", prompt=prompt_text)
            
            # 6. Parse the LLM result
            raw_text = llm_response["result"]
            llm_findings = self._extract_json(raw_text)

            # 7. Merge Findings
            all_findings = heuristic_findings + llm_findings

            requires_port_analysis = any(f.get("requires_port_analysis", False) for f in all_findings)

            return {
                "status": "success",
                "findings": all_findings,
                "requires_port_analysis": requires_port_analysis,
                "provider_info": {
                    "provider": llm_response["provider"],
                    "fallback_triggered": llm_response["fallback_triggered"]
                }
            }

    def _evaluate_elicitation_need(self, findings: List[Dict], events_json: str) -> Optional[Dict[str, Any]]:
        """
        Evaluates heuristic findings and raw events to determine if analyst input is needed.
        Returns an elicitation_request dict if input is needed, or None if analysis can proceed.
        All questions are batched into a single form.
        """
        fields = []
        context_items = {}

        # Parse events to find unique external IPs and internal IPs
        try:
            events = json.loads(events_json) if isinstance(events_json, str) else events_json
        except Exception:
            events = []

        internal_ips = set()
        external_ips = set()
        for evt in events:
            src = evt.get("id.orig_h", evt.get("src_ip", ""))
            dst = evt.get("id.resp_h", evt.get("dst_ip", ""))
            if src and src.startswith(("10.", "172.", "192.168.")):
                internal_ips.add(src)
            if dst and not dst.startswith(("10.", "172.", "192.168.")):
                external_ips.add(dst)

        # Trigger 1: Suspicious external IPs found
        if external_ips:
            top_external = list(external_ips)[:5]
            context_items["external_ips"] = top_external
            fields.append({
                "name": "expected_external_ips",
                "field_type": ElicitationFieldType.TEXTAREA.value,
                "label": f"The following external IPs were observed: {', '.join(top_external)}. Are any of these expected/approved destinations? List approved IPs, one per line.",
                "required": False,
                "default": ""
            })

        # Trigger 2: Asset criticality for flagged internal IPs
        flagged_ips = set()
        for f in findings:
            src = f.get("src_ip", f.get("source_ip", ""))
            dst = f.get("dst_ip", f.get("dest_ip", ""))
            if src:
                flagged_ips.add(src)
            if dst:
                flagged_ips.add(dst)

        if flagged_ips:
            context_items["flagged_internal_ips"] = list(flagged_ips)[:5]
            for ip in list(flagged_ips)[:3]:
                fields.append({
                    "name": f"asset_criticality_{ip.replace('.', '_')}",
                    "field_type": ElicitationFieldType.SELECT.value,
                    "label": f"What is the criticality level of {ip}?",
                    "options": ["Unknown", "Low - Dev/Test", "Medium - Standard workstation", "High - Production server", "Critical - Domain controller / Core infrastructure"],
                    "required": True,
                    "default": "Unknown"
                })

        # Trigger 3: Low confidence findings
        low_conf_findings = [f for f in findings if f.get("confidence", 1.0) < self.CONFIDENCE_THRESHOLD]
        if low_conf_findings:
            context_items["low_confidence_findings"] = [f.get("finding", f.get("title", "Unknown")) for f in low_conf_findings[:3]]
            fields.append({
                "name": "escalate_low_confidence",
                "field_type": ElicitationFieldType.RADIO.value,
                "label": f"There are {len(low_conf_findings)} low-confidence findings. Should they be escalated for deeper analysis?",
                "options": ["Yes — escalate all", "No — discard low-confidence findings", "Review individually after analysis"],
                "required": True,
                "default": "Review individually after analysis"
            })

        # Trigger 4: Beaconing detected — could be CDN/legitimate
        beaconing_findings = [f for f in findings if "beacon" in str(f).lower()]
        if beaconing_findings:
            context_items["beaconing_targets"] = [f.get("dst_ip", f.get("dest_ip", "Unknown")) for f in beaconing_findings[:3]]
            fields.append({
                "name": "beaconing_legitimate",
                "field_type": ElicitationFieldType.RADIO.value,
                "label": "Periodic/beaconing traffic was detected. Could this be legitimate (e.g., CDN polling, health checks)?",
                "options": ["Yes — likely legitimate, deprioritize", "No — treat as suspicious", "Unsure — needs further investigation"],
                "required": True,
                "default": "Unsure — needs further investigation"
            })

        # Only emit elicitation if we have questions
        if not fields:
            return None

        return {
            "status": "elicitation_needed",
            "elicitation_request": {
                "id": str(uuid.uuid4())[:8],
                "agent": "detection",
                "stage": "DETECTING",
                "title": "Detection Agent — Analyst Input Required",
                "description": "The detection engine has identified patterns that require human judgment before proceeding. Please review the context below and answer the questions.",
                "context": context_items,
                "fields": fields
            },
            "provider_info": {"provider": "none", "fallback_triggered": False}
        }

    def _extract_json(self, text: str) -> List[Dict[str, Any]]:
        try:
            # Very basic extraction logic
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except Exception as e:
            print(f"[!] Error parsing LLM JSON: {e}")
            return []
