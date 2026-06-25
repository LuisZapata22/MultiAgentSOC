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
        try:
            return self._call_claude(stage, prompt)
        except Exception as e:
            print(f"[!] Claude call failed: {e}. Falling back to Gemini...")
            try:
                result = self._call_gemini(prompt)
                return {"result": result, "provider": "gemini", "fallback_triggered": True, "error": str(e)}
            except Exception as e2:
                print(f"[!] Gemini fallback failed: {e2}. Falling back to Groq...")
                try:
                    result = self._call_groq(prompt)
                    return {"result": result, "provider": "groq", "fallback_triggered": True, "error": f"Claude: {e} | Gemini: {e2}"}
                except Exception as e3:
                    print(f"[!] Groq fallback also failed: {e3}")
                    # Return a degraded result instead of raising
                    return {
                        "result": "{}",
                        "provider": "none",
                        "fallback_triggered": True,
                        "error": f"Claude: {e} | Gemini: {e2} | Groq: {e3}"
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
        
        # Determine thinking budget based on stage
        # Report agent uses medium thinking (4096), others use lower thinking (1024)
        budget_tokens = 4096 if stage == "report" else 1024
        
        message = client.messages.create(
            max_tokens=8192,
            thinking={
                "type": "enabled",
                "budget_tokens": budget_tokens
            },
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="claude-sonnet-4-6",
        )
        return {"result": message.content[0].text, "provider": "claude", "fallback_triggered": False}
