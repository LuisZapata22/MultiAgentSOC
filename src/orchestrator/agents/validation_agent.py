import os
import json
from typing import Dict, Any, List
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter

class ValidationAgent:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.llm_router = LLMRouter()

    async def run_validation(self, all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Runs two-phase validation:
        Phase 1: Deterministic rule-based checks via the Validation MCP Server tool.
        Phase 2: LLM-based plain-language summary via the validation_summary_template prompt.
        """
        validation_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.validation.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )

        async with AsyncExitStack() as stack:
            val_read, val_write = await stack.enter_async_context(stdio_client(validation_params))
            val_session = await stack.enter_async_context(ClientSession(val_read, val_write))
            await val_session.initialize()

            # Phase 1: Deterministic validation (no LLM call)
            findings_json = json.dumps(all_findings)
            val_result = await val_session.call_tool(
                "validate_findings",
                arguments={"findings_json": findings_json}
            )
            validated_json = val_result.content[0].text if val_result.content else "{}"
            validated_report = json.loads(validated_json)
            
            print(f"[*] Deterministic validation complete. Summary: {validated_report.get('summary', {})}")

            # Phase 2: LLM Summary (uses Gemini/Groq)
            prompt_result = await val_session.get_prompt(
                "validation_summary_template",
                arguments={"validated_json": validated_json}
            )
            prompt_text = "\n".join([
                msg.content.text for msg in prompt_result.messages
                if msg.content.type == "text"
            ])

            print("[*] Calling LLM Router for Validation Summary...")
            llm_response = self.llm_router.call(stage="validation", prompt=prompt_text)

            raw_text = llm_response["result"]
            llm_summary = self._extract_json(raw_text)

            return {
                "status": "success",
                "deterministic_report": validated_report,
                "llm_summary": llm_summary,
                "provider_info": {
                    "provider": llm_response["provider"],
                    "fallback_triggered": llm_response["fallback_triggered"]
                }
            }

    def _extract_json(self, text: str) -> Dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except Exception as e:
            print(f"[!] Error parsing LLM JSON in Validation: {e}")
            return {"parse_error": str(e), "raw": text}
