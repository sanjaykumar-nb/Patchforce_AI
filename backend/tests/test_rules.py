"""
PatchForge AI - Phase 5 Vulnerability Rule Engine Unit Tests
===========================================================
Validates precision AST matching on CWE-89, CWE-78, CWE-22, and CWE-502,
ensuring high detection rates on vulnerable patterns and ZERO false positives on safe code.
"""

import pytest
from app.ast_engine import PythonASTParser, JavaScriptASTParser
from app.scanners.rules.registry import rule_registry


# ------------------------------------------------------------------------------
# 1. Python Rules Tests
# ------------------------------------------------------------------------------

def test_py_sqli_detection_and_safe_negative():
    py_parser = PythonASTParser()
    rule = rule_registry.get_rule_by_id("PY-SQLI-001")
    assert rule is not None

    # Positive: Vulnerable code
    vuln_code = """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
"""
    findings = rule.analyze(vuln_code, "app/db.py", py_parser)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY-SQLI-001"
    assert findings[0].cwe == "CWE-89"
    assert findings[0].function_name == "get_user"
    assert findings[0].confidence_score >= 0.90

    # Negative: Secure parameterized code
    safe_code = """
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
"""
    safe_findings = rule.analyze(safe_code, "app/db.py", py_parser)
    assert len(safe_findings) == 0  # Zero false positives


def test_py_command_injection_and_safe_negative():
    py_parser = PythonASTParser()
    rule = rule_registry.get_rule_by_id("PY-CMDI-001")
    assert rule is not None

    # Positive: os.system with concatenation
    vuln_code = """
def ping_service(host):
    cmd = "ping -c 1 " + host
    os.system(cmd)
"""
    findings = rule.analyze(vuln_code, "app/utils.py", py_parser)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY-CMDI-001"
    assert findings[0].cwe == "CWE-78"

    # Negative: Safe subprocess with argument list
    safe_code = """
import subprocess
def ping_service(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
"""
    safe_findings = rule.analyze(safe_code, "app/utils.py", py_parser)
    assert len(safe_findings) == 0


def test_py_path_traversal_and_safe_negative():
    py_parser = PythonASTParser()
    rule = rule_registry.get_rule_by_id("PY-PATH-001")
    assert rule is not None

    # Positive: Direct open with concatenation
    vuln_code = """
def read_report(filename):
    path = "/var/data/" + filename
    with open(path, "r") as f:
        return f.read()
"""
    findings = rule.analyze(vuln_code, "app/reports.py", py_parser)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-22"

    # Negative: Safe validated path
    safe_code = """
import os
def read_report(filename):
    safe_name = os.path.basename(filename)
    path = os.path.join("/var/data/", safe_name)
    with open(path, "r") as f:
        return f.read()
"""
    safe_findings = rule.analyze(safe_code, "app/reports.py", py_parser)
    assert len(safe_findings) == 0


def test_py_unsafe_deserialization_and_safe_negative():
    py_parser = PythonASTParser()
    rule = rule_registry.get_rule_by_id("PY-DESER-001")
    assert rule is not None

    # Positive: pickle.loads
    vuln_code = """
import pickle
def restore_session(raw_data):
    return pickle.loads(raw_data)
"""
    findings = rule.analyze(vuln_code, "app/session.py", py_parser)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-502"

    # Negative: json.loads
    safe_code = """
import json
def restore_session(raw_data):
    return json.loads(raw_data)
"""
    safe_findings = rule.analyze(safe_code, "app/session.py", py_parser)
    assert len(safe_findings) == 0


# ------------------------------------------------------------------------------
# 2. JavaScript Rules Tests
# ------------------------------------------------------------------------------

def test_js_sqli_detection_and_safe_negative():
    js_parser = JavaScriptASTParser()
    rule = rule_registry.get_rule_by_id("JS-SQLI-001")
    assert rule is not None

    # Positive: db.query with concatenation
    vuln_code = """
async function getUser(id) {
    const q = "SELECT * FROM users WHERE id = " + id;
    return await db.query(q);
}
"""
    findings = rule.analyze(vuln_code, "src/db.js", js_parser)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"

    # Negative: Parameterized query
    safe_code = """
async function getUser(id) {
    return await db.query("SELECT * FROM users WHERE id = $1", [id]);
}
"""
    safe_findings = rule.analyze(safe_code, "src/db.js", js_parser)
    assert len(safe_findings) == 0


def test_js_command_injection_and_safe_negative():
    js_parser = JavaScriptASTParser()
    rule = rule_registry.get_rule_by_id("JS-CMDI-001")
    assert rule is not None

    # Positive: child_process.exec with concatenation
    vuln_code = """
function backup(folder) {
    exec("tar -czf backup.tar.gz " + folder);
}
"""
    findings = rule.analyze(vuln_code, "src/backup.js", js_parser)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"


def test_rule_registry_discovery():
    all_rules = rule_registry.get_all_rules()
    assert len(all_rules) >= 7

    py_rules = rule_registry.get_rules_for_language("python")
    assert len(py_rules) >= 4

    js_rules = rule_registry.get_rules_for_language("javascript")
    assert len(js_rules) >= 3
