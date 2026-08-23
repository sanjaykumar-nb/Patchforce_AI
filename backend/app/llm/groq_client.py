"""
PatchForge AI - Groq Cloud LLM Client
======================================
Communicates with Groq's hosted inference API (OpenAI-compatible chat
completions) for AST-targeted patch generation. Groq's free tier needs no
credit card and is fast enough that patch generation doesn't need the
cold-start/timeout handling a self-hosted small model does - the same
retry-on-truncation and structural-completeness hardening still applies,
since any hosted LLM can still return an incomplete or malformed response.
"""

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
import httpx

from app.config import get_settings
from app.llm.prompts import prompt_builder
from app.llm.fallback_patches import generate_fallback_patch
from app.core.logging import get_logger

logger = get_logger("patchforge.llm.groq_client")
settings = get_settings()


class GroqClient:
    """Production client for Groq's hosted Code LLM inference API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.api_key = api_key or settings.GROQ_API_KEY
        self.model = model or settings.GROQ_MODEL
        self.timeout = timeout or settings.GROQ_TIMEOUT_SECONDS
        self.base_url = "https://api.groq.com/openai/v1"

    def check_health(self) -> bool:
        """Checks whether a Groq API key is configured and the API is reachable."""
        if not self.api_key:
            return False
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.debug(f"Groq health check failed: {str(e)}")
            return False

    def list_models(self) -> List[str]:
        """Lists model IDs available to this Groq account."""
        if not self.api_key:
            return []
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                if resp.status_code == 200:
                    return [m.get("id", "") for m in resp.json().get("data", []) if m.get("id")]
        except Exception as e:
            logger.warning(f"Failed to list Groq models: {str(e)}")
        return []

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> str:
        """Sends a chat completion request to Groq and returns the raw response text."""
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            with httpx.Client(timeout=float(self.timeout)) as client:
                resp = client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                choice = data["choices"][0]
                if choice.get("finish_reason") == "length":
                    raise ValueError("Groq response was truncated (finish_reason=length) before completion")
                return choice["message"]["content"] or ""
        except Exception as e:
            logger.error(f"Groq LLM generation request failed: {str(e)}")
            raise e

    def _extract_json(self, raw_text: str) -> Dict[str, Any]:
        """Robust JSON extractor handling markdown codeblocks and escaped strings."""
        cleaned = raw_text.strip()

        if "```" in cleaned:
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
            if match:
                cleaned = match.group(1).strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(cleaned[start : end + 1])
            raise ValueError(f"Could not parse structured JSON from LLM output: {raw_text[:200]}")

    def generate_structured_patch(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_attempts: int = 3,
        validate_patched_code: Optional[Callable[[str], Tuple[bool, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Generates a validated structured patch JSON object using Groq, with
        automated fallback to deterministic template remediation if Groq is
        unavailable or every attempt fails.
        """
        sys_prompt = system_prompt or prompt_builder.get_system_prompt()

        if self.check_health():
            last_error: Optional[str] = None
            for attempt in range(1, max_attempts + 1):
                try:
                    raw_response = self.generate(
                        prompt=prompt,
                        system_prompt=sys_prompt,
                        temperature=0.1,
                        json_mode=True,
                    )
                    patch_json = self._extract_json(raw_response)

                    required_keys = ["explanation", "original_code", "patched_code", "imports_to_add", "risk_level", "confidence"]
                    for k in required_keys:
                        if k not in patch_json:
                            if k == "imports_to_add":
                                patch_json[k] = []
                            elif k == "risk_level":
                                patch_json[k] = "LOW"
                            elif k == "confidence":
                                patch_json[k] = 0.90
                            elif k in ("explanation", "original_code", "patched_code"):
                                patch_json[k] = ""

                    patched_code = patch_json.get("patched_code")
                    if not patched_code:
                        last_error = "response parsed but 'patched_code' was empty"
                        logger.warning(f"Groq attempt {attempt}/{max_attempts} produced no patched_code, retrying...")
                        continue

                    if validate_patched_code:
                        is_valid, reason = validate_patched_code(patched_code)
                        if not is_valid:
                            last_error = reason
                            logger.warning(f"Groq attempt {attempt}/{max_attempts} produced incomplete patched_code ({reason}), retrying...")
                            continue

                    return patch_json
                except Exception as e:
                    last_error = str(e)
                    logger.warning(f"Groq attempt {attempt}/{max_attempts} failed ({last_error}), retrying...")

            logger.warning(f"Groq generation failed after {max_attempts} attempts ({last_error}). Engaging fallback rule generator.")

        # Deterministic Fallback Generator
        return generate_fallback_patch(prompt)


# Global singleton instance
groq_client = GroqClient()
