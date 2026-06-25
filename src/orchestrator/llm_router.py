import os
from typing import Dict, Any
from dotenv import load_dotenv

class LLMRouter:
    def __init__(self):
        load_dotenv()
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        self.groq_key = os.getenv("GROQ_API_KEY")
        self.claude_key = os.getenv("ANTHROPIC_API_KEY")
        self.environment = os.getenv("ENVIRONMENT", "dev").lower()

    def call(self, stage: str, prompt: str, **kwargs) -> Dict[str, Any]:
        """
        Routes an LLM call to the appropriate provider based on the environment and stage.
        """
        if self.environment == "prod":
            try:
                return self._call_claude(stage, prompt)
            except Exception as e:
                print(f"[!] Claude call failed in PROD: {e}. Falling back to Gemini...")
                return self._fallback_chain(prompt, e)
        else:
            # DEV environment uses Gemini/Groq only
            return self._fallback_chain(prompt, None)

    def _fallback_chain(self, prompt: str, initial_error: Exception | None) -> Dict[str, Any]:
        try:
            result = self._call_gemini(prompt)
            # If initial_error is not None, it means we fell back from Claude
            is_fallback = initial_error is not None
            return {"result": result, "provider": "gemini", "fallback_triggered": is_fallback, "error": str(initial_error) if initial_error else None}
        except Exception as e2:
            print(f"[!] Gemini failed: {e2}. Falling back to Groq...")
            try:
                result = self._call_groq(prompt)
                err_msg = f"Claude: {initial_error} | " if initial_error else ""
                err_msg += f"Gemini: {e2}"
                return {"result": result, "provider": "groq", "fallback_triggered": True, "error": err_msg}
            except Exception as e3:
                print(f"[!] Groq fallback also failed: {e3}")
                err_msg = f"Claude: {initial_error} | " if initial_error else ""
                err_msg += f"Gemini: {e2} | Groq: {e3}"
                return {
                    "result": "{}",
                    "provider": "none",
                    "fallback_triggered": True,
                    "error": err_msg
                }

    def _call_gemini(self, prompt: str) -> str:
        if not self.gemini_key:
            raise ValueError("GEMINI_API_KEY is missing.")
        from google import genai
        client = genai.Client(api_key=self.gemini_key)
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=prompt,
        )
        return response.text

    def _call_groq(self, prompt: str) -> str:
        if not self.groq_key:
            raise ValueError("GROQ_API_KEY is missing.")
        from groq import Groq
        client = Groq(api_key=self.groq_key)
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="openai/gpt-oss-120b",
        )
        return chat_completion.choices[0].message.content

    def _call_claude(self, stage: str, prompt: str) -> Dict[str, Any]:
        if not self.claude_key:
            raise ValueError("ANTHROPIC_API_KEY is missing.")
        from anthropic import Anthropic
        client = Anthropic(api_key=self.claude_key)

        # budget_tokens must be less than max_tokens
        budget_tokens = 4096 if stage == "report" else 1024
        max_tokens = budget_tokens + 4096  # headroom for the actual response

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=max_tokens,
            thinking={
                "type": "enabled",
                "budget_tokens": budget_tokens,
            },
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        # With thinking enabled, content blocks are: [thinking_block, ..., text_block]
        # Find the text block explicitly rather than assuming index 0
        text_block = next(
            (block for block in message.content if block.type == "text"), None
        )
        if text_block is None:
            raise ValueError("No text block found in Claude response.")

        return {
            "result": text_block.text,
            "provider": "claude",
            "fallback_triggered": False,
        }
