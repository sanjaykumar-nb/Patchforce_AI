"""
PatchForge AI - LLM Client & Prompt Engineering Package
========================================================
Groq Cloud API integration (default), local Ollama client (available for
anyone self-hosting a model), prompt injection defenses, and structured
patch generation.
"""

from app.llm.client import OllamaClient, ollama_client
from app.llm.groq_client import GroqClient, groq_client
from app.llm.prompts import RemediationPromptBuilder, prompt_builder

__all__ = [
    "OllamaClient",
    "ollama_client",
    "GroqClient",
    "groq_client",
    "RemediationPromptBuilder",
    "prompt_builder",
]
