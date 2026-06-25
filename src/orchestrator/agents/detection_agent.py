import os
import json
import asyncio
from typing import Dict, Any, List
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter

class DetectionAgent:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.llm_router = LLMRouter()

    async def run_detection(self) -> Dict[str, Any]:
        """
        Fetches normalized events, gets the detection prompt, and routes to the LLM.
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

            # 1. Fetch Events (increase limit so we actually capture the malicious traces at the end of the file)
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

            # 3. Get Prompt Template (passing in heuristics so LLM doesn't duplicate them)
            prompt_result = await det_session.get_prompt(
                "detection_reasoning_template", 
                arguments={
                    "events_json": events_json, 
                    "heuristic_findings_json": heuristic_findings_json
                }
            )
            # The prompt result returns a list of messages. We just concatenate them into a string for the LLMRouter
            prompt_text = "\n".join([msg.content.text for msg in prompt_result.messages if msg.content.type == "text"])

            # 4. Call LLM Router for Enrichment
            print("[*] Calling LLM Router for Advanced Detection...")
            llm_response = self.llm_router.call(stage="detection", prompt=prompt_text)
            
            # 5. Parse the LLM result
            raw_text = llm_response["result"]
            llm_findings = self._extract_json(raw_text)

            # 6. Merge Findings
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
