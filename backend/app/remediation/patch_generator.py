"""
PatchForge AI - AST-Targeted Minimal Patch Generator
====================================================
Generates minimal, non-breaking, syntactically precise code replacements
for verified vulnerabilities using Code LLMs and AST context extraction.
"""

from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.models import (
    Vulnerability,
    VulnerabilityStatus,
    Patch,
    PatchStatus,
    AuditLog,
)
from app.ast_engine import ASTContextExtractor
from app.llm import groq_client, prompt_builder
from app.remediation.diff_utils import (
    generate_unified_diff,
    merge_imports,
    splice_function_replacement,
)
from app.core.source_resolver import read_source_for_vulnerability
from app.core.patch_quality import check_structural_completeness
from app.core.logging import get_logger

logger = get_logger("patchforge.remediation.patch_generator")


class PatchGenerator:
    """Orchestrates AST context slicing, Code LLM invocation, and diff production."""

    def __init__(self):
        self.context_extractor = ASTContextExtractor()
        self.llm_client = groq_client

    def generate_patch_for_vulnerability(
        self,
        db: Session,
        vulnerability: Vulnerability,
        source_code_override: Optional[str] = None,
    ) -> Patch:
        """
        Generates a minimal AST-targeted patch and persists candidate in database.
        """
        logger.info(f"Generating patch for Vulnerability [{vulnerability.id}] ({vulnerability.cwe})...")

        # 1. Resolve full source code
        if source_code_override:
            full_source = source_code_override
        else:
            full_source = read_source_for_vulnerability(vulnerability)

        # 2. Extract AST context
        ast_context = self.context_extractor.extract_context(
            source_code=full_source,
            file_path=vulnerability.file_path,
            line_start=vulnerability.line_start,
            line_end=vulnerability.line_end,
            rule_id=vulnerability.rule_id,
            cwe=vulnerability.cwe,
            severity=vulnerability.severity.value,
            description=vulnerability.description,
        )

        target_code = (
            ast_context.get("target_code_to_patch")
            or ast_context.get("target_code")
            or vulnerability.source_snippet
        )
        raw_imports = ast_context.get("imports", [])
        existing_imports = [
            imp if isinstance(imp, str) else imp.get("text", "")
            for imp in raw_imports
        ]

        # 3. Build prompt and query Code LLM
        prompt = prompt_builder.build_prompt(
            language=ast_context.get("language", "python"),
            cwe=vulnerability.cwe,
            description=vulnerability.description,
            file_path=vulnerability.file_path,
            function_name=vulnerability.function_name,
            source_snippet=target_code,
            enclosing_scope=ast_context.get("enclosing_scope"),
            existing_imports=existing_imports,
        )

        language = ast_context.get("language", "python")
        llm_response = self.llm_client.generate_structured_patch(
            prompt,
            validate_patched_code=lambda code: check_structural_completeness(target_code, code, language),
        )

        explanation = llm_response.get("explanation", "Remediated security flaw via AST replacement.")
        # The model is no longer asked to echo the original code back (it's
        # redundant - we already have it precisely via AST extraction - and
        # asking for it only made truncation more likely on longer functions).
        old_code = target_code
        new_code = llm_response.get("patched_code") or target_code
        imports_to_add = llm_response.get("imports_to_add", [])
        confidence = float(llm_response.get("confidence", 0.90))

        # 4. Splice replacement into full file
        patched_source = splice_function_replacement(
            full_source=full_source,
            old_function_code=old_code,
            new_function_code=new_code,
        )

        # 5. Merge new imports into header
        patched_source_with_imports = merge_imports(
            source_code=patched_source,
            imports_to_add=imports_to_add,
            language=ast_context.get("language", "python"),
        )

        # 6. Generate unified diff
        diff_content = generate_unified_diff(
            original_code=full_source,
            patched_code=patched_source_with_imports,
            file_path=vulnerability.file_path,
        )

        # 7. Persist Patch entity
        patch = Patch(
            vulnerability_id=vulnerability.id,
            scan_id=vulnerability.scan_id,
            model_name=self.llm_client.model,
            diff_content=diff_content,
            old_code=old_code,
            new_code=new_code,
            explanation=explanation,
            security_reason=f"Remediates {vulnerability.cwe} ({vulnerability.rule_id}) with confidence {confidence:.2f}.",
            status=PatchStatus.PENDING_VALIDATION,
        )
        db.add(patch)

        # Update vulnerability status
        vulnerability.status = VulnerabilityStatus.PATCH_GENERATED
        db.add(vulnerability)

        # Record Audit Log
        audit = AuditLog(
            event_type="PATCH_GENERATED",
            actor="PATCH_GENERATOR",
            repository_id=vulnerability.repository_id,
            vulnerability_id=vulnerability.id,
            patch_id=patch.id,
            details=f'{{"model": "{self.llm_client.model}", "cwe": "{vulnerability.cwe}", "confidence": {confidence}}}',
        )
        db.add(audit)
        db.commit()
        db.refresh(patch)

        logger.info(f"Patch [{patch.id}] generated successfully for Vulnerability [{vulnerability.id}].")
        return patch


# Global singleton instance
patch_generator = PatchGenerator()
