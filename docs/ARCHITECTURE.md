# PatchForge AI — Deep Technical Architecture & AST Engine Specification

---

## 1. Abstract Syntax Tree (AST) Engine

PatchForge AI utilizes native C-bindings for **Tree-sitter** grammars (Python & JavaScript). Unlike regex or heuristic grep-based scanners:
- **Zero Syntax Ambiguity**: Tree-sitter builds a concrete syntax tree representing the exact semantics executed by language runtimes.
- **TreeCursor Traversal**: Implements preorder linear memory traversal using TreeCursor, eliminating dynamic heap allocations during recursive scans.
- **Targeted Scope Extraction**: Given any arbitrary line number finding, the AST engine identifies the smallest enclosing function or class definition (`function_definition`, `function_declaration`, `arrow_function`) to restrict LLM patch synthesis boundaries.

---

## 2. Multi-Stage Patch Validation Algorithm

Every patch synthesized by the Code LLM must pass four sequential verification stages before acceptance:

```
[ LLM Unified Diff Output ]
            │
            ▼
 ┌────────────────────────────────────────────────────────┐
 │ Stage 1: Syntax Parsing & Compilation                  │
 │ - Parses patched file with Tree-sitter parser           │
 │ - Rejects syntax errors, unbalanced braces/indentation │
 └──────────────────────────┬─────────────────────────────┘
                            │ Pass (Syntax OK)
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │ Stage 2: AST Function Scope Enclosure                  │
 │ - Compares AST before and after patch                  │
 │ - Asserts modifications remain strictly inside target  │
 │ - Rejects hallucinated file-wide changes               │
 └──────────────────────────┬─────────────────────────────┘
                            │ Pass (Scope OK)
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │ Stage 3: Dynamic Sandbox Exploit Neutralization        │
 │ - Re-executes the confirmed PoC against patched code   │
 │ - Asserts exploit fails / is safely blocked            │
 └──────────────────────────┬─────────────────────────────┘
                            │ Pass (Exploit Blocked)
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │ Stage 4: Clean AST Security Re-scan                    │
 │ - Executes all rule scanners against modified file     │
 │ - Asserts 0 new CWE vulnerabilities introduced         │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
  [ Composite Score >= 80/100 -> Eligible for GitHub PR ]
```

---

## 3. Sandboxing & Isolation Guarantees

All dynamic exploit verifications execute inside hardened Docker containers:
- `--cap-drop=ALL`: Strips all Linux root capabilities.
- `--read-only`: Mounts root filesystem as strictly read-only.
- `--tmpfs /tmp`: Ephemeral in-memory scratch space (128MB max).
- `--network none`: Drops all network access (no external exfiltration).
- `--memory=512m --cpus=1.0`: Strict cgroup resource bounds.
- 15-second wall-clock execution timeout.
