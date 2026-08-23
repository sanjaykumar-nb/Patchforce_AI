"""
PatchForge AI - Pull Request Markdown Description Generator
===========================================================
Constructs comprehensive, executive-ready GitHub Pull Request descriptions
detailing vulnerability findings, validation scores, and unified diffs.
"""

from typing import Optional
from app.models import Vulnerability, Patch


def generate_pr_markdown_description(
    vulnerability: Vulnerability,
    patch: Patch,
    poc_output: Optional[str] = None,
) -> str:
    """Generates structured Markdown body for automated GitHub Pull Requests."""
    syntax_status = "✅ PASSED (20/20)" if patch.syntax_valid else "❌ FAILED (0/20)"
    ast_status = "✅ PASSED (20/20)" if patch.ast_valid else "❌ FAILED (0/20)"
    test_status = f"✅ PASSED ({int(patch.test_pass_rate * 30)}/30)" if patch.test_pass_rate >= 1.0 else f"⚠️ PARTIAL ({int(patch.test_pass_rate * 30)}/30)"
    rescan_status = "✅ CLEAN (30/30)" if patch.rescan_clean else "❌ FLAGGED (0/30)"

    sev_str = vulnerability.severity.value if hasattr(vulnerability.severity, "value") else str(vulnerability.severity or "HIGH")

    body = f"""## 🛡️ PatchForge AI Autonomous Remediation

### 📋 Vulnerability Summary
- **Vulnerability Type**: `{vulnerability.cwe}`
- **Security Rule**: `{vulnerability.rule_id}`
- **Severity**: `{sev_str}` (CVSS: {vulnerability.cvss_score or 7.5})
- **Target File**: `{vulnerability.file_path}`
- **Enclosing Function**: `{vulnerability.function_name or 'Global Scope'}` (Lines {vulnerability.line_start}-{vulnerability.line_end})

---

### 🔍 Vulnerability Description
> {vulnerability.description}

---

### 🤖 LLM Remediation Rationale
{patch.explanation}

**Security Hardening Detail**:
{patch.security_reason}

---

### 🧪 4-Stage Multi-Tier Validation Report
| Validation Stage | Result | Weight |
| :--- | :---: | :---: |
| **1. Syntax Integrity** | {syntax_status} | 20% |
| **2. AST Scope Preservation** | {ast_status} | 20% |
| **3. Sandboxed Dynamic Verification** | {test_status} | 30% |
| **4. Security Re-Scan** | {rescan_status} | 30% |
| **Overall Composite Score** | **`{patch.patch_score:.1f} / 100.0`** | **100%** |

---

### 📦 Unified Code Diff
```diff
{patch.diff_content}
```

---
*Generated autonomously by **[PatchForge AI](https://github.com/patchforge-ai)** — AST-driven automated vulnerability remediation.*
"""
    return body.strip()
