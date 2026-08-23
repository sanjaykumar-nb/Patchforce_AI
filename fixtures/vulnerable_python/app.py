"""
PatchForge AI - Safe Synthetic Vulnerability Test Fixture (Python)
==================================================================
Intentionally vulnerable controlled test application for AST detection and patching.
DO NOT USE IN PRODUCTION.
"""

import os
import sqlite3
import pickle
from typing import Optional


def get_user_profile(user_id: str) -> Optional[dict]:
    """CWE-89 SQL Injection Vulnerability."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, name TEXT);")
    cursor.execute("INSERT INTO users VALUES ('1', 'Alice');")
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def ping_server(hostname: str):
    """CWE-78 Command Injection Vulnerability."""
    cmd = "ping -c 1 " + hostname
    os.system(cmd)


def read_user_file(filename: str) -> str:
    """CWE-22 Path Traversal Vulnerability."""
    file_path = "/data/storage/" + filename
    with open(file_path, "r") as f:
        return f.read()


def load_cached_session(session_blob: bytes):
    """CWE-502 Unsafe Deserialization Vulnerability."""
    return pickle.loads(session_blob)
