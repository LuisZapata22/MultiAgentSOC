import os
import json
import asyncio
from typing import Dict, Any, List
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter

class PortAnalyzerAgent:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.llm_router = LLMRouter()

    async def run_port_analysis(self, previous_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Fetches normalized events, gets the port analysis prompt, and routes to the LLM.
        """
        evidence_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.evidence.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )
        port_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.port_analysis.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )

        async with AsyncExitStack() as stack:
            # Connect to Evidence Server
            ev_read, ev_write = await stack.enter_async_context(stdio_client(evidence_params))
            ev_session = await stack.enter_async_context(ClientSession(ev_read, ev_write))
            await ev_session.initialize()

            # Connect to Port Analysis Server
            port_read, port_write = await stack.enter_async_context(stdio_client(port_params))
            port_session = await stack.enter_async_context(ClientSession(port_read, port_write))
            await port_session.initialize()

            # 1. Fetch Events (limit to 50 for the POC)
            ev_result = await ev_session.call_tool("read_evidence", arguments={"limit": 50, "offset": 0})
            events_json = ev_result.content[0].text if ev_result.content else "[]"
            
            # 2. Convert previous findings to string
            previous_findings_json = json.dumps(previous_findings)

            # 3. Get Prompt Template
            prompt_result = await port_session.get_prompt(
                "port_reasoning_template", 
                arguments={
                    "events_json": events_json,
                    "previous_findings_json": previous_findings_json
                }
            )
            prompt_text = "\n".join([msg.content.text for msg in prompt_result.messages if msg.content.type == "text"])

            # 4. Call LLM Router
            print("[*] Calling LLM Router for Port Analysis...")
            llm_response = self.llm_router.call(stage="port_analysis", prompt=prompt_text)
            
            # 5. Parse the result
            raw_text = llm_response["result"]
            findings = self._extract_json(raw_text)

            return {
                "status": "success",
                "findings": findings,
                "provider_info": {
                    "provider": llm_response["provider"],
                    "fallback_triggered": llm_response["fallback_triggered"]
                }
            }

    def _extract_json(self, text: str) -> List[Dict[str, Any]]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except Exception as e:
            print(f"[!] Error parsing LLM JSON in Port Analysis: {e}")
            return []
