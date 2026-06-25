import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from ..llm_router import LLMRouter


SYSTEM_PROMPT = """You are a Security Analyst Assistant for an Agentic SOC platform.

## HARD CONSTRAINTS
1. You ONLY answer questions about the report, findings, evidence, and analysis artifacts provided in the CONTEXT below.
2. You must NEVER speculate or fabricate information not present in the context.
3. You must NEVER reveal API keys, credentials, internal system paths, or configuration details.
4. You must NEVER access or reference data from other reports, sessions, or external sources.
5. If information is not available in the context, respond with: "This information is not available in the current report."

## RESPONSE GUIDELINES
- Cite specific findings by their ID, title, or MITRE technique when applicable.
- Explain reasoning in plain, professional language suitable for a SOC analyst.
- When referencing severity levels or confidence scores, include the exact values from the report.
- Structure responses with bullet points or numbered lists when presenting multiple items.
- Keep responses concise but thorough.

## CONTEXT — CURRENT REPORT
{report_context}

## CONTEXT — AGENT TRACES (Inter-Agent Communication Log)
{traces_context}

## CONTEXT — HUMAN-IN-THE-LOOP DECISIONS
{elicitation_context}

## CONTEXT — ALL FINDINGS (Raw)
{findings_context}

## CONTEXT — VALIDATION RESULTS
{validation_context}
"""


class ChatAgent:
    """
    Post-report conversational assistant.
    Maintains conversation memory scoped to the current report session.
    Routes through LLMRouter (Gemini in dev, Claude in prod).
    Can optionally query MCP servers for deeper drill-down.
    """

    def __init__(
        self,
        report: Dict[str, Any],
        traces: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        validation_result: Dict[str, Any],
        elicitation_history: List[Dict[str, Any]],
    ):
        self.llm_router = LLMRouter()
        self.project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', '..', '..')
        )
        self.conversation_history: List[Dict[str, str]] = []

        # Build the static context once — it never changes for this report
        self._system_prompt = SYSTEM_PROMPT.format(
            report_context=json.dumps(report, indent=2, default=str),
            traces_context=json.dumps(traces, indent=2, default=str),
            elicitation_context=json.dumps(elicitation_history, indent=2, default=str),
            findings_context=json.dumps(findings, indent=2, default=str),
            validation_context=json.dumps(validation_result, indent=2, default=str),
        )

    async def ask(self, user_message: str) -> Dict[str, Any]:
        """
        Process a user question about the current report.
        Returns the assistant response and any sources cited.
        """
        self.conversation_history.append({"role": "user", "content": user_message})

        # Build the full prompt with conversation history
        prompt = self._build_prompt(user_message)

        # Check if we need MCP drill-down for evidence queries
        needs_evidence = any(
            kw in user_message.lower()
            for kw in ["evidence", "raw event", "packet", "log entr", "original data", "source ip", "dest ip", "port "]
        )

        mcp_context = ""
        if needs_evidence:
            mcp_context = await self._query_evidence_server(user_message)
            if mcp_context:
                prompt += f"\n\n## ADDITIONAL EVIDENCE FROM MCP SERVER\n{mcp_context}\n"

        # Route through LLM
        try:
            llm_response = self.llm_router.call(stage="chat", prompt=prompt)
            assistant_message = llm_response.get("result", "I was unable to process your question.")
            provider = llm_response.get("provider", "unknown")
        except Exception as e:
            assistant_message = f"An error occurred while processing your question: {str(e)}"
            provider = "error"

        self.conversation_history.append({"role": "assistant", "content": assistant_message})

        return {
            "response": assistant_message,
            "provider": provider,
            "mcp_queried": needs_evidence and bool(mcp_context),
        }

    def get_history(self) -> List[Dict[str, str]]:
        """Returns the full conversation history."""
        return self.conversation_history

    def _build_prompt(self, current_question: str) -> str:
        """
        Builds the full LLM prompt: system prompt + conversation history + current question.
        Limits history to last 10 exchanges to stay within token limits.
        """
        parts = [self._system_prompt]

        # Include recent conversation history (last 10 exchanges = 20 messages)
        recent_history = self.conversation_history[:-1]  # exclude the just-added user msg
        if recent_history:
            history_window = recent_history[-20:]
            parts.append("\n## CONVERSATION HISTORY")
            for msg in history_window:
                role_label = "Analyst" if msg["role"] == "user" else "Assistant"
                parts.append(f"{role_label}: {msg['content']}")

        parts.append(f"\n## CURRENT QUESTION\nAnalyst: {current_question}")
        parts.append("\nAssistant:")

        return "\n".join(parts)

    async def _query_evidence_server(self, question: str) -> str:
        """
        Queries the Evidence MCP Server to fetch raw events for deeper drill-down.
        Returns a string summary or empty string if unavailable.
        """
        evidence_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.evidence.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root),
        )

        try:
            async with AsyncExitStack() as stack:
                ev_read, ev_write = await stack.enter_async_context(
                    stdio_client(evidence_params)
                )
                ev_session = await stack.enter_async_context(
                    ClientSession(ev_read, ev_write)
                )
                await ev_session.initialize()

                # Fetch a sample of events for context
                ev_result = await ev_session.call_tool(
                    "read_evidence", arguments={"limit": 50, "offset": 0}
                )
                events_text = ev_result.content[0].text if ev_result.content else "[]"

                # Truncate if too long to avoid token overflow
                if len(events_text) > 8000:
                    events_text = events_text[:8000] + "\n... (truncated)"

                return events_text
        except Exception as e:
            print(f"[!] ChatAgent: Failed to query Evidence MCP Server: {e}")
            return ""
