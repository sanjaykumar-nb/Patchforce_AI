"""
PatchForge AI - LLM Patch Structural Completeness Check
========================================================
Lightweight sanity check that a generated patch's function body has the same
control-flow "shape" as the original - specifically, that a trailing return
statement isn't silently dropped.

This exists to catch content-level truncation: a small quantized model can run
out of its output budget mid-function while Ollama's JSON-format grammar still
force-closes the response into syntactically valid JSON. The result parses fine
and passes plain syntax validation (ast.parse succeeds on a function ending in
a bare assignment), but the function is functionally incomplete - e.g. it builds
a query and never executes it, silently returning None for every call. The
system prompt already promises callers "same function signature and return
types", so a dropped trailing return is a strong, low-false-positive signal of
truncation rather than a deliberate rewrite.
"""

import ast
from typing import Optional, Tuple


def _python_function_ends_with_return(source: str) -> Optional[bool]:
    """True/False if determinable, None if the source doesn't parse or has no function."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not functions or not functions[0].body:
        return None

    return isinstance(functions[0].body[-1], ast.Return)


def check_python_structural_completeness(original_code: str, patched_code: str) -> Tuple[bool, str]:
    """Verifies the patched Python function preserves a trailing return if the original had one."""
    original_returns = _python_function_ends_with_return(original_code)
    patched_returns = _python_function_ends_with_return(patched_code)

    if original_returns is None or patched_returns is None:
        return True, "Structural completeness check skipped (not a single-function body)."

    if original_returns and not patched_returns:
        return False, "Patched function dropped the original's trailing return statement - likely truncated generation."

    return True, "Structural completeness check passed."


def _javascript_function_ends_with_return(source: str) -> Optional[bool]:
    """True/False if determinable, None if the source doesn't parse or has no function body."""
    from app.ast_engine.javascript_parser import JavaScriptASTParser

    parser = JavaScriptASTParser()
    tree = parser.parse(source)
    if not tree or not tree.root_node or tree.root_node.has_error:
        return None

    for node in parser._walk_tree(tree):
        if node.type in ("function_declaration", "function_expression", "arrow_function", "method_definition"):
            body = node.child_by_field_name("body")
            if body and body.type == "statement_block":
                statements = body.named_children
                if not statements:
                    return None
                return statements[-1].type == "return_statement"

    return None


def check_javascript_structural_completeness(original_code: str, patched_code: str) -> Tuple[bool, str]:
    """Verifies the patched JavaScript function preserves a trailing return if the original had one."""
    original_returns = _javascript_function_ends_with_return(original_code)
    patched_returns = _javascript_function_ends_with_return(patched_code)

    if original_returns is None or patched_returns is None:
        return True, "Structural completeness check skipped (not a single-function body)."

    if original_returns and not patched_returns:
        return False, "Patched function dropped the original's trailing return statement - likely truncated generation."

    return True, "Structural completeness check passed."


def check_structural_completeness(original_code: str, patched_code: str, language: str) -> Tuple[bool, str]:
    """Dispatches to the language-appropriate structural completeness check."""
    if language == "javascript":
        return check_javascript_structural_completeness(original_code, patched_code)
    return check_python_structural_completeness(original_code, patched_code)
