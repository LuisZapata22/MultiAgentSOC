import os
import json
import uuid
from typing import Dict, Any, List, Optional
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter
from ..models import ElicitationFieldType


class ValidationAgent:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.llm_router = LLMRouter()

    async def run_validation(self, all_findings: List[Dict[str, Any]], user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs two-phase validation:
        Phase 1: Deterministic rule-based checks via the Validation MCP Server tool.
        Phase 2: LLM-based plain-language summary via the validation_summary_template prompt.
        If user_context is provided, it's injected into the LLM prompt.
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

            # Check for elicitation need BEFORE calling LLM
            if user_context is None:
                elicitation = self._evaluate_elicitation_need(validated_report)
                if elicitation is not None:
                    return elicitation

            # Phase 2: LLM Summary
            prompt_result = await val_session.get_prompt(
                "validation_summary_template",
                arguments={"validated_json": validated_json}
            )
            prompt_text = "\n".join([
                msg.content.text for msg in prompt_result.messages
                if msg.content.type == "text"
            ])

            # Inject analyst context if provided
            if user_context:
                context_str = "\n".join([f"- {k}: {v}" for k, v in user_context.items()])
                prompt_text += f"\n\n=== ANALYST-PROVIDED CONTEXT ===\nThe analyst has provided the following additional context for validation:\n{context_str}\nAdjust your validation summary accordingly.\n"

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

    def _evaluate_elicitation_need(self, validated_report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates the deterministic validation report and determines if analyst input is needed.
        Returns an elicitation_request dict if input is needed, or None.
        All questions are batched into a single form.
        """
        fields = []
        context_items = {}

        validated_findings = validated_report.get("validated_findings", [])
        summary = validated_report.get("summary", {})

        # Trigger 1: Findings with REVIEW_NEEDED status
        review_needed = [f for f in validated_findings if f.get("status") == "REVIEW_NEEDED"]
        if review_needed:
            context_items["review_needed_findings"] = [
                {"finding": f.get("finding", "Unknown"), "reason": f.get("reason", "")}
                for f in review_needed[:5]
            ]
            fields.append({
                "name": "accept_review_needed",
                "field_type": ElicitationFieldType.RADIO.value,
                "label": f"There are {len(review_needed)} findings with REVIEW_NEEDED status (insufficient evidence for automatic confirmation). How should they be handled?",
                "options": [
                    "Accept all as confirmed findings",
                    "Mark all as informational only",
                    "Discard all — likely false positives",
                    "Keep as REVIEW_NEEDED for manual triage"
                ],
                "required": True,
                "default": "Keep as REVIEW_NEEDED for manual triage"
            })

        # Trigger 2: UNCONFIRMED findings — multiple interpretations possible
        unconfirmed = [f for f in validated_findings if f.get("status") == "UNCONFIRMED"]
        if unconfirmed:
            context_items["unconfirmed_findings"] = [
                {"finding": f.get("finding", "Unknown"), "reason": f.get("reason", "")}
                for f in unconfirmed[:5]
            ]
            fields.append({
                "name": "handle_unconfirmed",
                "field_type": ElicitationFieldType.RADIO.value,
                "label": f"There are {len(unconfirmed)} UNCONFIRMED findings that couldn't be validated automatically. Should they be included in the report?",
                "options": [
                    "Yes — include for completeness",
                    "No — exclude from the report",
                    "Include but flag as low-confidence"
                ],
                "required": True,
                "default": "Include but flag as low-confidence"
            })

        # Trigger 3: Any findings with no MITRE mapping
        no_mitre = [f for f in validated_findings if not f.get("mitre_technique_id")]
        if no_mitre and len(no_mitre) > 0:
            fields.append({
                "name": "additional_context",
                "field_type": ElicitationFieldType.TEXTAREA.value,
                "label": f"{len(no_mitre)} findings have no MITRE ATT&CK mapping. Can you provide additional context about the environment or expected traffic patterns?",
                "required": False,
                "default": ""
            })

        # Only emit elicitation if we have questions
        if not fields:
            return None

        return {
            "status": "elicitation_needed",
            "elicitation_request": {
                "id": str(uuid.uuid4())[:8],
                "agent": "validation",
                "stage": "VALIDATING",
                "title": "Validation Agent — Analyst Review Required",
                "description": "The validation engine has identified findings that require human judgment before finalizing. Please review the evidence below and provide your assessment.",
                "context": context_items,
                "fields": fields
            },
            "provider_info": {"provider": "none", "fallback_triggered": False}
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
