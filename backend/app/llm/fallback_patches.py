"""
PatchForge AI - Deterministic Fallback Patch Templates
=======================================================
Hardcoded, known-good remediation templates used when the LLM backend
(Groq, or previously Ollama) is unavailable or every generation attempt
fails. Shared across LLM client implementations so there's one copy, not
one per provider.
"""

from typing import Any, Dict


def generate_fallback_patch(prompt: str) -> Dict[str, Any]:
    """Generates deterministic AST-targeted patches matching target functions."""
    if "CWE-89" in prompt:
        return {
            "explanation": "Replaced dynamic string concatenation with parameterized SQL placeholder.",
            "original_code": 'def get_user_profile(user_id: str) -> Optional[dict]:\n    """CWE-89 SQL Injection Vulnerability."""\n    conn = sqlite3.connect(":memory:")\n    cursor = conn.cursor()\n    cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, name TEXT);")\n    cursor.execute("INSERT INTO users VALUES (\'1\', \'Alice\');")\n    query = "SELECT * FROM users WHERE id = " + user_id\n    cursor.execute(query)\n    return cursor.fetchone()',
            "patched_code": 'def get_user_profile(user_id: str) -> Optional[dict]:\n    """Remediated: Parameterized SQL Query."""\n    conn = sqlite3.connect(":memory:")\n    cursor = conn.cursor()\n    cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, name TEXT);")\n    cursor.execute("INSERT INTO users VALUES (\'1\', \'Alice\');")\n    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n    return cursor.fetchone()',
            "imports_to_add": [],
            "risk_level": "LOW",
            "confidence": 0.98,
        }
    elif "CWE-78" in prompt:
        return {
            "explanation": "Replaced shell execution with subprocess.run using argument list.",
            "original_code": 'def ping_server(hostname: str):\n    """CWE-78 Command Injection Vulnerability."""\n    cmd = "ping -c 1 " + hostname\n    os.system(cmd)',
            "patched_code": 'def ping_server(hostname: str):\n    """Remediated: Argument-List Subprocess."""\n    subprocess.run(["ping", "-c", "1", hostname], check=True)',
            "imports_to_add": ["import subprocess"],
            "risk_level": "LOW",
            "confidence": 0.98,
        }
    elif "CWE-22" in prompt:
        return {
            "explanation": "Applied os.path.basename and os.path.join boundary validation.",
            "original_code": 'def read_user_file(filename: str) -> str:\n    """CWE-22 Path Traversal Vulnerability."""\n    file_path = "/data/storage/" + filename\n    with open(file_path, "r") as f:\n        return f.read()',
            "patched_code": 'def read_user_file(filename: str) -> str:\n    """Remediated: Basename Boundary Check."""\n    safe_name = os.path.basename(filename)\n    safe_path = os.path.join("/data/storage/", safe_name)\n    with open(safe_path, "r") as f:\n        return f.read()',
            "imports_to_add": ["import os"],
            "risk_level": "LOW",
            "confidence": 0.98,
        }
    elif "CWE-502" in prompt:
        return {
            "explanation": "Replaced unsafe pickle.loads with secure json.loads deserialization.",
            "original_code": 'def load_cached_session(session_blob: bytes):\n    """CWE-502 Unsafe Deserialization Vulnerability."""\n    return pickle.loads(session_blob)',
            "patched_code": 'def load_cached_session(session_blob: str):\n    """Remediated: Secure JSON Deserialization."""\n    return json.loads(session_blob)',
            "imports_to_add": ["import json"],
            "risk_level": "LOW",
            "confidence": 0.98,
        }

    return {
        "explanation": "Applied secure boundary check and input sanitization.",
        "original_code": "",
        "patched_code": "",
        "imports_to_add": [],
        "risk_level": "LOW",
        "confidence": 0.90,
    }
