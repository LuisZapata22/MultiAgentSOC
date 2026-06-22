import os
from typing import Dict, Any
from dotenv import load_dotenv

class LLMRouter:
    def __init__(self):
        load_dotenv()
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        self.groq_key = os.getenv("GROQ_API_KEY")
        self.claude_key = os.getenv("ANTHROPIC_API_KEY")

    def call(self, stage: str, prompt: str, **kwargs) -> Dict[str, Any]:
        """
        Routes an LLM call to the appropriate provider based on the stage.
        """
        if stage == "report":
            try:
                return self._call_claude(prompt)
            except Exception as e:
                print(f"[!] Claude call failed: {e}. Returning degraded result.")
                return {"result": "{}", "provider": "none", "fallback_triggered": True, "error": str(e)}
        else:
            # Try Gemini first
            try:
                result = self._call_gemini(prompt)
                return {"result": result, "provider": "gemini", "fallback_triggered": False}
            except Exception as e:
                print(f"[!] Gemini call failed: {e}. Falling back to Groq...")
                try:
                    result = self._call_groq(prompt)
                    return {"result": result, "provider": "groq", "fallback_triggered": True}
                except Exception as e2:
                    print(f"[!] Groq fallback also failed: {e2}")
                    # Return a degraded result instead of raising — deterministic layers still have value
                    return {
                        "result": "{}",
                        "provider": "none",
                        "fallback_triggered": True,
                        "error": f"Gemini: {e} | Groq: {e2}"
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

    def _call_claude(self, prompt: str) -> Dict[str, Any]:
        if not self.claude_key:
            raise ValueError("ANTHROPIC_API_KEY is missing.")
        from anthropic import Anthropic
        client = Anthropic(api_key=self.claude_key)
        message = client.messages.create(
            max_tokens=4096,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="claude-sonnet-4-6",
        )
        return {"result": message.content[0].text, "provider": "claude", "fallback_triggered": False}
