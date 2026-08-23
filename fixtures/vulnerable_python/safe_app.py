"""
PatchForge AI - Safe Synthetic Test Fixture (Python)
====================================================
Secure reference implementations matching app.py for zero-false-positive validation.
"""

import os
import json
import sqlite3
import subprocess
from typing import Optional


def get_user_profile(user_id: str) -> Optional[dict]:
    """Secure Parameterized SQL Query."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, name TEXT);")
    cursor.execute("INSERT INTO users VALUES ('1', 'Alice');")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def ping_server(hostname: str):
    """Secure Argument-List Subprocess Execution."""
    subprocess.run(["ping", "-c", "1", hostname], check=True)


def read_user_file(filename: str) -> str:
    """Secure Basename Boundary File Access."""
    safe_name = os.path.basename(filename)
    safe_path = os.path.join("/data/storage/", safe_name)
    with open(safe_path, "r") as f:
        return f.read()


def load_cached_session(session_blob: str):
    """Secure JSON Deserialization."""
    return json.loads(session_blob)
