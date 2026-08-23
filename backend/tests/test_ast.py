"""
PatchForge AI - Phase 4 Tree-sitter AST Engine Unit Tests
=========================================================
Validates multi-language syntactic analysis, call-site extraction,
scope resolution, and targeted LLM context extraction for Python and JavaScript.
"""

import pytest
from app.ast_engine import (
    PythonASTParser,
    JavaScriptASTParser,
    ASTContextExtractor,
)

PYTHON_SAMPLE_CODE = """import os
import sqlite3
from typing import Optional

class UserManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE id = " + user_id
        cursor.execute(query)
        result = cursor.fetchone()
        return result

    def ping_host(self, host: str):
        command = "ping -c 1 " + host
        os.system(command)
"""

JAVASCRIPT_SAMPLE_CODE = """const { exec } = require('child_process');
const db = require('./database');

class AuthService {
    constructor() {
        this.authenticated = false;
    }

    async findUser(username) {
        const sql = "SELECT * FROM accounts WHERE name = '" + username + "'";
        return await db.query(sql);
    }
}

function runDiagnostics(host) {
    exec("ping -c 1 " + host, (err, stdout) => {
        console.log(stdout);
    });
}
"""


def test_python_ast_parser_functions_and_classes():
    parser = PythonASTParser()
    functions = parser.get_functions(PYTHON_SAMPLE_CODE)
    classes = parser.get_classes(PYTHON_SAMPLE_CODE)

    assert len(classes) == 1
    assert classes[0].identifier == "UserManager"

    func_names = [f.identifier for f in functions]
    assert "__init__" in func_names
    assert "get_user_by_id" in func_names
    assert "ping_host" in func_names


def test_python_ast_parser_imports_and_calls():
    parser = PythonASTParser()
    imports = parser.get_imports(PYTHON_SAMPLE_CODE)
    calls = parser.get_calls(PYTHON_SAMPLE_CODE)

    assert len(imports) == 3
    import_texts = [i.text for i in imports]
    assert any("import os" in text for text in import_texts)
    assert any("sqlite3" in text for text in import_texts)

    call_names = [c.identifier for c in calls if c.identifier]
    assert any("cursor.execute" in name or "execute" in name for name in call_names)
    assert any("os.system" in name or "system" in name for name in call_names)


def test_python_enclosing_function_resolution():
    parser = PythonASTParser()
    # Line 12 is: query = "SELECT * FROM users WHERE id = " + user_id
    enclosing = parser.find_enclosing_function(PYTHON_SAMPLE_CODE, line_number=12)
    assert enclosing is not None
    assert enclosing.identifier == "get_user_by_id"
    assert enclosing.start_line <= 12 <= enclosing.end_line


def test_javascript_ast_parser_functions_and_calls():
    parser = JavaScriptASTParser()
    functions = parser.get_functions(JAVASCRIPT_SAMPLE_CODE)
    classes = parser.get_classes(JAVASCRIPT_SAMPLE_CODE)
    imports = parser.get_imports(JAVASCRIPT_SAMPLE_CODE)
    calls = parser.get_calls(JAVASCRIPT_SAMPLE_CODE)

    assert len(classes) == 1
    assert classes[0].identifier == "AuthService"

    func_names = [f.identifier for f in functions]
    assert "findUser" in func_names
    assert "runDiagnostics" in func_names

    assert len(imports) >= 2  # require('child_process'), require('./database')

    call_names = [c.identifier for c in calls if c.identifier]
    assert any("exec" in name for name in call_names)


def test_javascript_enclosing_function_resolution():
    parser = JavaScriptASTParser()
    # Line 10 is inside findUser()
    enclosing = parser.find_enclosing_function(JAVASCRIPT_SAMPLE_CODE, line_number=10)
    assert enclosing is not None
    assert enclosing.identifier == "findUser"


def test_targeted_ast_context_extractor_python():
    extractor = ASTContextExtractor()
    payload = extractor.extract_context(
        source_code=PYTHON_SAMPLE_CODE,
        file_path="app/user_manager.py",
        line_start=12,
        line_end=13,
        rule_id="PY-SQLI-001",
        cwe="CWE-89",
        severity="HIGH",
        description="SQL injection via string concatenation in execute().",
    )

    assert payload["language"] == "python"
    assert payload["function_name"] == "get_user_by_id"
    assert payload["enclosing_scope"] == "UserManager.get_user_by_id"
    assert payload["vulnerability"]["cwe"] == "CWE-89"
    assert len(payload["imports"]) == 3
    assert "def get_user_by_id" in payload["target_code_to_patch"]
    assert "def ping_host" not in payload["target_code_to_patch"]  # Confirms precise function-level isolation!
    assert len(payload["security_constraints"]) > 0


def test_targeted_ast_context_extractor_javascript():
    extractor = ASTContextExtractor()
    payload = extractor.extract_context(
        source_code=JAVASCRIPT_SAMPLE_CODE,
        file_path="src/services/auth.js",
        line_start=10,
        line_end=11,
        rule_id="JS-SQLI-001",
        cwe="CWE-89",
        severity="HIGH",
        description="SQL injection in db.query()",
    )

    assert payload["language"] == "javascript"
    assert payload["function_name"] == "findUser"
    assert "findUser" in payload["target_code_to_patch"]
    assert "runDiagnostics" not in payload["target_code_to_patch"]  # Unrelated function excluded
