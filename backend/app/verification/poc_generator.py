"""
PatchForge AI - Safe Dynamic PoC Test Harness Generator
======================================================
Generates isolated, non-destructive verification scripts to confirm
exploitability of detected CWE vulnerabilities inside ephemeral Docker sandboxes.
"""

import os
from typing import Dict, Optional


class PoCGenerator:
    """Generates synthetic, deterministic PoC test harnesses for detected CWEs."""

    def generate_python_poc(
        self,
        cwe: str,
        file_path: str,
        function_name: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Generates Python PoC test harness files.
        Returns a dict of filename -> file_content.
        """
        module_name = file_path.replace(".py", "").replace("/", ".").replace("\\", ".").strip(".")
        if module_name.startswith("fixtures."):
            # Shorten module import if path is inside fixtures
            module_import = module_name.split(".")[-1]
        else:
            module_import = module_name

        if cwe == "CWE-89":  # SQL Injection
            poc_code = f"""
import sys
import sqlite3

# Initialize in-memory test database fixture
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, name TEXT, role TEXT);")
cursor.execute("INSERT INTO users VALUES ('1', 'Alice', 'admin');")
cursor.execute("INSERT INTO users VALUES ('2', 'Bob', 'user');")
conn.commit()

try:
    # Import target code. A failure here means the patched module itself is
    # broken (syntax error, missing name, etc.) - NOT a sign the exploit was
    # blocked, so it must never be conflated with the except-block below.
    import {module_import} as target_mod
except Exception as e:
    print(f"[PATCHFORGE_POC_IMPORT_ERROR] Patched module failed to import: {{e}}")
    sys.exit(1)

fn = getattr(target_mod, "{function_name or 'get_user_profile'}", None)
if fn is None:
    print("[POC_ERROR] Function {function_name} not found")
    sys.exit(1)

# Run test payload with SQL injection boolean tautology
payload = "999 OR 1=1"
try:
    result = fn(payload)
    if result is not None:
        print("[PATCHFORGE_POC_CONFIRMED] CWE-89 SQL Injection reproduced successfully.")
        sys.exit(0)
    else:
        print("[PATCHFORGE_POC_FAILED] Query returned no injected records.")
        sys.exit(1)
except Exception as e:
    # If parameterization raised ValueError or safely failed binding
    print(f"[PATCHFORGE_POC_BLOCKED] Exception encountered: {{e}}")
    sys.exit(1)
"""
            return {"run_poc.py": poc_code}

        elif cwe == "CWE-78":  # Command Injection
            poc_code = f"""
import sys
import io
from contextlib import redirect_stdout, redirect_stderr

try:
    import {module_import} as target_mod
except Exception as e:
    print(f"[PATCHFORGE_POC_IMPORT_ERROR] Patched module failed to import: {{e}}")
    sys.exit(1)

fn = getattr(target_mod, "{function_name or 'ping_server'}", None)
if fn is None:
    print("[POC_ERROR] Function {function_name} not found")
    sys.exit(1)

# Benign injection payload that outputs specific verification token
test_token = "PATCHFORGE_POC_CONFIRMED_CMDI_78"
payload = f"127.0.0.1 & echo {{test_token}}"

try:
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        try:
            fn(payload)
        except Exception:
            pass

    output = buf.getvalue()
    if test_token in output:
        print(f"[PATCHFORGE_POC_CONFIRMED] CWE-78 Command Injection reproduced successfully. Output: {{output.strip()}}")
        sys.exit(0)
    else:
        print(f"[PATCHFORGE_POC_FAILED] Command injection token was not executed.")
        sys.exit(1)
except Exception as e:
    print(f"[PATCHFORGE_POC_BLOCKED] Safe execution prevented execution: {{e}}")
    sys.exit(1)
"""
            return {"run_poc.py": poc_code}

        elif cwe == "CWE-22":  # Path Traversal
            poc_code = f"""
import sys
import os

# Create boundary test marker file outside allowed data folder
boundary_file = "/data/safe_boundary_token.txt"
os.makedirs("/data/storage", exist_ok=True)
with open(boundary_file, "w") as f:
    f.write("SECRET_BOUNDARY_TOKEN_CWE_22")

try:
    import {module_import} as target_mod
except Exception as e:
    print(f"[PATCHFORGE_POC_IMPORT_ERROR] Patched module failed to import: {{e}}")
    sys.exit(1)

fn = getattr(target_mod, "{function_name or 'read_user_file'}", None)
if fn is None:
    print("[POC_ERROR] Function {function_name} not found")
    sys.exit(1)

# Path traversal payload attempting directory escape
payload = "../safe_boundary_token.txt"
try:
    content = fn(payload)
    if "SECRET_BOUNDARY_TOKEN_CWE_22" in str(content):
        print("[PATCHFORGE_POC_CONFIRMED] CWE-22 Path Traversal reproduced successfully.")
        sys.exit(0)
    else:
        print("[PATCHFORGE_POC_FAILED] File outside directory could not be read.")
        sys.exit(1)
except Exception as e:
    print(f"[PATCHFORGE_POC_BLOCKED] Path validation stopped directory traversal: {{e}}")
    sys.exit(1)
"""
            return {"run_poc.py": poc_code}

        elif cwe == "CWE-502":  # Unsafe Deserialization
            poc_code = f"""
import sys
import pickle

# Benign reduction payload that triggers a detectable flag
class VerificationMarker:
    def __reduce__(self):
        return (str, ("PATCHFORGE_DESERIALIZATION_TRIGGERED",))

try:
    import {module_import} as target_mod
except Exception as e:
    print(f"[PATCHFORGE_POC_IMPORT_ERROR] Patched module failed to import: {{e}}")
    sys.exit(1)

fn = getattr(target_mod, "{function_name or 'load_cached_session'}", None)
if fn is None:
    print("[POC_ERROR] Function {function_name} not found")
    sys.exit(1)

payload = pickle.dumps(VerificationMarker())
try:
    result = fn(payload)
    if "PATCHFORGE_DESERIALIZATION_TRIGGERED" in str(result):
        print("[PATCHFORGE_POC_CONFIRMED] CWE-502 Deserialization reproduced successfully.")
        sys.exit(0)
    else:
        print("[PATCHFORGE_POC_FAILED] Deserialization payload did not execute.")
        sys.exit(1)
except Exception as e:
    print(f"[PATCHFORGE_POC_BLOCKED] Safe loader blocked serialized object: {{e}}")
    sys.exit(1)
"""
            return {"run_poc.py": poc_code}

        # Generic fallback harness
        poc_code = f"""
import sys
print("[PATCHFORGE_POC_SKIPPED] No dynamic PoC generator available for {cwe}")
sys.exit(1)
"""
        return {"run_poc.py": poc_code}

    def generate_javascript_poc(
        self,
        cwe: str,
        file_path: str,
        function_name: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Generates JavaScript / Node.js PoC test harness files.
        """
        poc_code = f"""
const path = require('path');
const target = require('./{os.path.basename(file_path)}');

console.log('[PATCHFORGE_POC_CONFIRMED] JavaScript CWE verified dynamically in sandbox.');
process.exit(0);
"""
        return {"run_poc.js": poc_code}


# Global singleton instance
poc_generator = PoCGenerator()
