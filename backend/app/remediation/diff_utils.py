"""
PatchForge AI - AST Diff & Code Splicing Utilities
==================================================
Provides precision function replacement, import deduplication,
and unified git diff formatting for minimal code change footprints.
"""

import difflib
from typing import List, Optional


def generate_unified_diff(
    original_code: str,
    patched_code: str,
    file_path: str = "app.py",
) -> str:
    """Generates standard unified git diff format."""
    orig_lines = original_code.splitlines(keepends=True)
    patch_lines = patched_code.splitlines(keepends=True)

    diff = difflib.unified_diff(
        orig_lines,
        patch_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(diff)


def merge_imports(source_code: str, imports_to_add: List[str], language: str = "python") -> str:
    """
    Inserts required imports into the header of the source code
    without duplicating existing imports.
    """
    if not imports_to_add:
        return source_code

    lines = source_code.splitlines()
    existing_text = source_code

    new_imports = [
        imp.strip()
        for imp in imports_to_add
        if imp.strip() and imp.strip() not in existing_text
    ]

    if not new_imports:
        return source_code

    # Find position of last import in file
    insert_idx = 0
    if language == "python":
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                insert_idx = i + 1
            elif stripped.startswith("class ") or stripped.startswith("def "):
                break
    else:  # JavaScript
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "require(" in stripped or stripped.startswith("import "):
                insert_idx = i + 1
            elif stripped.startswith("function ") or stripped.startswith("class ") or "const " in stripped:
                break

    for imp in reversed(new_imports):
        lines.insert(insert_idx, imp)

    return "\n".join(lines)


def splice_function_replacement(
    full_source: str,
    old_function_code: str,
    new_function_code: str,
) -> str:
    """
    Replaces the exact old function implementation within the full file
    while preserving indentation and surrounding functions.
    """
    old_cleaned = old_function_code.strip()
    new_cleaned = new_function_code.strip()

    if old_cleaned in full_source:
        return full_source.replace(old_cleaned, new_cleaned, 1)

    # Line-by-line fallback replacement
    old_lines = [l.strip() for l in old_cleaned.splitlines() if l.strip()]
    if not old_lines:
        return full_source

    first_line = old_lines[0]
    source_lines = full_source.splitlines()

    start_idx = -1
    for i, line in enumerate(source_lines):
        if first_line in line:
            start_idx = i
            break

    if start_idx != -1:
        # Detect indentation of first line
        orig_line = source_lines[start_idx]
        indent = orig_line[: len(orig_line) - len(orig_line.lstrip())]

        indented_new = []
        for line in new_cleaned.splitlines():
            indented_new.append(indent + line if line.strip() else line)

        end_idx = min(start_idx + len(old_lines), len(source_lines))
        source_lines[start_idx:end_idx] = indented_new
        return "\n".join(source_lines)

    return full_source
