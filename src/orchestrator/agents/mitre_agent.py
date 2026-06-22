import os
import json
from typing import Dict, Any, List
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter

class MitreAgent:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.llm_router = LLMRouter()

    async def run_mitre_mapping(self, previous_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Connects to the MITRE Server for taxonomy and reasoning templates,
        then maps previous findings to MITRE ATT&CK techniques.
        """
        mitre_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.mitre.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )

        async with AsyncExitStack() as stack:
            # Connect to MITRE Server
            mitre_read, mitre_write = await stack.enter_async_context(stdio_client(mitre_params))
            mitre_session = await stack.enter_async_context(ClientSession(mitre_read, mitre_write))
            await mitre_session.initialize()

            # Convert previous findings to string
            findings_json = json.dumps(previous_findings)

            # Get Prompt Template
            prompt_result = await mitre_session.get_prompt(
                "mitre_mapping_template", 
                arguments={
                    "findings_json": findings_json
                }
            )
            prompt_text = "\n".join([msg.content.text for msg in prompt_result.messages if msg.content.type == "text"])

            # Call LLM Router
            print("[*] Calling LLM Router for MITRE Mapping...")
            llm_response = self.llm_router.call(stage="mitre", prompt=prompt_text)
            
            # Parse the result
            raw_text = llm_response["result"]
            mapped_findings = self._extract_json(raw_text)

            # Merge mapped findings back with original evidence where possible, or just return mapping
            return {
                "status": "success",
                "mitre_mappings": mapped_findings,
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
            print(f"[!] Error parsing LLM JSON in MITRE Mapping: {e}")
            return []
