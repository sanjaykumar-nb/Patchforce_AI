"""
PatchForge AI - Local Ollama Code LLM Client
============================================
Communicates with local Ollama daemon (qwen2.5-coder, codellama, deepseek-coder)
with structured JSON schema enforcement, timeouts, and fallback resilience.
"""

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
import httpx

from app.config import get_settings
from app.llm.prompts import prompt_builder
from app.llm.fallback_patches import generate_fallback_patch
from app.core.logging import get_logger

logger = get_logger("patchforge.llm.client")
settings = get_settings()


class OllamaClient:
    """Production client for local Code LLMs running via Ollama."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL
        self.timeout = timeout or settings.OLLAMA_TIMEOUT_SECONDS

    def check_health(self) -> bool:
        """Checks if the local Ollama service is reachable and responsive."""
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception as e:
            logger.debug(f"Ollama health check failed: {str(e)}")
            return False

    def list_models(self) -> List[str]:
        """Lists all downloaded models available in the local Ollama instance."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    models = resp.json().get("models", [])
                    return [m.get("name", "") for m in models if m.get("name")]
        except Exception as e:
            logger.warning(f"Failed to list Ollama models: {str(e)}")
        return []

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> str:
        """Sends generation request to Ollama and returns the raw response text."""
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": 0.9,
                # Explicit output budget so a longer function body can't be silently
                # cut off mid-JSON by whatever the model's/Ollama's implicit default is.
                "num_predict": 1536,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt
        if json_mode:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=float(self.timeout)) as client:
                resp = client.post(f"{self.base_url}/api/generate", json=payload)
                resp.raise_for_status()
                data = resp.json()
                if data.get("done") is False:
                    raise ValueError("Ollama returned an incomplete response (done=false) - generation was cut off before completion")
                return data.get("response", "")
        except Exception as e:
            logger.error(f"Ollama LLM generation request failed: {str(e)}")
            raise e

    def _extract_json(self, raw_text: str) -> Dict[str, Any]:
        """Robust JSON extractor handling markdown codeblocks and escaped strings."""
        cleaned = raw_text.strip()
        
        # Strip markdown codeblocks ```json ... ``` if present
        if "```" in cleaned:
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
            if match:
                cleaned = match.group(1).strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Attempt to find outermost { ... }
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                substring = cleaned[start : end + 1]
                return json.loads(substring)
            raise ValueError(f"Could not parse structured JSON from LLM output: {raw_text[:200]}")

    def generate_structured_patch(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_attempts: int = 3,
        validate_patched_code: Optional[Callable[[str], Tuple[bool, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Generates a validated structured patch JSON object using Ollama,
        with automated fallback to deterministic template remediation if Ollama is unavailable.

        Small quantized models occasionally return incomplete/truncated JSON on a
        given attempt (see `generate()`'s done=false check and `_extract_json`'s
        parse failure) - this is retried a few times before falling back, since a
        retry at the same temperature frequently succeeds where the prior attempt
        didn't.

        `validate_patched_code`, if given, receives the candidate `patched_code`
        string and returns (is_valid, reason). This catches a subtler failure
        JSON-level checks miss: the model runs out of output budget mid-function
        while the JSON envelope still gets force-closed into syntactically valid
        JSON, producing code that parses fine but is functionally incomplete
        (e.g. a query that's built but never executed). A rejection here is
        treated the same as any other failed attempt and retried.
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

                    # Validate required schema keys
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
                        logger.warning(f"Ollama attempt {attempt}/{max_attempts} produced no patched_code, retrying...")
                        continue

                    if validate_patched_code:
                        is_valid, reason = validate_patched_code(patched_code)
                        if not is_valid:
                            last_error = reason
                            logger.warning(f"Ollama attempt {attempt}/{max_attempts} produced incomplete patched_code ({reason}), retrying...")
                            continue

                    return patch_json
                except Exception as e:
                    last_error = str(e)
                    logger.warning(f"Ollama attempt {attempt}/{max_attempts} failed ({last_error}), retrying...")

            logger.warning(f"Ollama generation failed after {max_attempts} attempts ({last_error}). Engaging fallback rule generator.")

        # Deterministic Fallback Generator
        return self._generate_fallback_patch(prompt)

    def _generate_fallback_patch(self, prompt: str) -> Dict[str, Any]:
        """Generates deterministic AST-targeted patches matching target functions."""
        return generate_fallback_patch(prompt)


# Global singleton instance
ollama_client = OllamaClient()
