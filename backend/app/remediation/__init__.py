"""
PatchForge AI - Automated Remediation Package
=============================================
AST-targeted patch generation, unified diff production, and code splicing.
"""

from app.remediation.diff_utils import (
    generate_unified_diff,
    merge_imports,
    splice_function_replacement,
)
from app.remediation.patch_generator import PatchGenerator, patch_generator

__all__ = [
    "generate_unified_diff",
    "merge_imports",
    "splice_function_replacement",
    "PatchGenerator",
    "patch_generator",
]
