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

            # 1. Fetch Events (limit to 50 for the POC so we don't blow up context window immediately)
            ev_result = await ev_session.call_tool("read_evidence", arguments={"limit": 50, "offset": 0})
            events_json = ev_result.content[0].text if ev_result.content else "[]"

            # 2. Get Prompt Template
            prompt_result = await det_session.get_prompt("detection_reasoning_template", arguments={"events_json": events_json})
            # The prompt result returns a list of messages. We just concatenate them into a string for the LLMRouter
            prompt_text = "\n".join([msg.content.text for msg in prompt_result.messages if msg.content.type == "text"])

            # 3. Call LLM Router
            print("[*] Calling LLM Router for Detection...")
            llm_response = self.llm_router.call(stage="detection", prompt=prompt_text)
            
            # 4. Parse the result and determine next steps
            # Since the LLM returns a markdown block usually, we try to extract the JSON.
            raw_text = llm_response["result"]
            findings = self._extract_json(raw_text)

            requires_port_analysis = any(f.get("requires_port_analysis", False) for f in findings)

            return {
                "status": "success",
                "findings": findings,
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
