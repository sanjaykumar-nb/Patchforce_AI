"""
PatchForge AI - Phase 9 Code LLM Client & Prompt Tests
======================================================
Validates prompt injection delimiters, Ollama health checks, model discovery,
structured JSON extraction, and live AI patch proposal generation.
"""

import pytest
from app.llm import OllamaClient, ollama_client, RemediationPromptBuilder, prompt_builder


def test_prompt_builder_delimiters_and_guardrails():
    builder = RemediationPromptBuilder()
    prompt = builder.build_prompt(
        language="python",
        cwe="CWE-89",
        description="SQL injection in cursor.execute",
        file_path="app/db.py",
        function_name="get_user",
        source_snippet="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        enclosing_scope="UserRepo.get_user",
        existing_imports=["import os", "import sqlite3"],
    )

    assert "<<<<CODE_START>>>>" in prompt
    assert "<<<<CODE_END>>>>" in prompt
    assert "CWE-89" in prompt
    assert "UserRepo.get_user" in prompt
    assert "import sqlite3" in prompt


def test_ollama_client_json_extractor_markdown():
    client = OllamaClient()

    # Raw JSON
    raw_json = '{"explanation": "Fixed SQLi", "original_code": "a", "patched_code": "b", "imports_to_add": [], "risk_level": "LOW", "confidence": 0.98}'
    parsed1 = client._extract_json(raw_json)
    assert parsed1["explanation"] == "Fixed SQLi"

    # Markdown block
    markdown_json = 'Here is the fix:\n```json\n{"explanation": "Fixed SQLi", "original_code": "a", "patched_code": "b", "imports_to_add": [], "risk_level": "LOW", "confidence": 0.98}\n```'
    parsed2 = client._extract_json(markdown_json)
    assert parsed2["confidence"] == 0.98


def test_ollama_health_and_model_listing():
    client = OllamaClient()
    # Check if local Ollama daemon is active
    if client.check_health():
        models = client.list_models()
        assert len(models) >= 1
        assert any("qwen2.5-coder" in m for m in models)


def test_ollama_generate_structured_patch():
    client = OllamaClient()
    prompt = prompt_builder.build_prompt(
        language="python",
        cwe="CWE-89",
        description="SQL Injection via string concatenation",
        file_path="app/db.py",
        function_name="get_user",
        source_snippet="""def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()""",
    )

    patch_result = client.generate_structured_patch(prompt)

    assert "explanation" in patch_result
    assert "original_code" in patch_result
    assert "patched_code" in patch_result
    assert "imports_to_add" in patch_result
    assert "risk_level" in patch_result
    assert "confidence" in patch_result
    assert isinstance(patch_result["imports_to_add"], list)
    assert isinstance(patch_result["confidence"], (int, float))


def test_ollama_fallback_patch_generator():
    client = OllamaClient()
    patch_sqli = client._generate_fallback_patch("Vulnerability: CWE-89 SQL Injection")
    assert "parameterized" in patch_sqli["explanation"].lower()
    assert "%s" in patch_sqli["patched_code"]

    patch_cmdi = client._generate_fallback_patch("Vulnerability: CWE-78 Command Injection")
    assert "subprocess.run" in patch_cmdi["patched_code"]
    assert "import subprocess" in patch_cmdi["imports_to_add"]
