# PatchForge AI — Autonomous AST-Driven Vulnerability Remediation Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg)](https://fastapi.tiangolo.com)
[![React 18](https://img.shields.io/badge/React-18.2-61DAFB.svg)](https://reactjs.org/)
[![Tree-sitter](https://img.shields.io/badge/Tree--sitter-0.21.3-brightgreen.svg)](https://tree-sitter.github.io/)
[![Security: Bandit Clean](https://img.shields.io/badge/Security-Bandit%20Clean-success.svg)](https://bandit.readthedocs.io/)

> **Autonomous DevSecOps Engine** that continuously detects OWASP Top 10 vulnerabilities via multi-language Tree-sitter Abstract Syntax Trees (AST), dynamically reproduces exploits in isolated Docker sandboxes, synthesizes targeted minimal function patches via local Code LLMs (`qwen2.5-coder`), validates fixes across 4 strict quality gates, and automatically submits scored GitHub Pull Requests.

---

##  System Architecture

```
                                 [ Source Repositories ]
                                            │
                             (GitHub Webhook / Push Event)
                                            ▼
                           ┌─────────────────────────────────┐
                           │   FastAPI Ingestion Gateway     │
                           │   (HMAC-SHA256 Timing Attack Def)│
                           └────────────────┬────────────────┘
                                            │
                                            ▼
                           ┌─────────────────────────────────┐
                           │ Multi-Language Tree-sitter AST  │
                           │ Zero-Allocation TreeCursor Scan │
                           └────────────────┬────────────────┘
                                            │ (CWE Finding Detected)
                                            ▼
                           ┌─────────────────────────────────┐
                           │  Isolated Docker Sandbox PoC    │
                           │  (CapDrop:ALL, ReadOnly, NoNet) │
                           └────────────────┬────────────────┘
                                            │ (Exploit Confirmed)
                                            ▼
                           ┌─────────────────────────────────┐
                           │  Local Ollama Code LLM Client   │
                           │  (Targeted Function Synthesis)  │
                           └────────────────┬────────────────┘
                                            │ (Patch Generated)
                                            ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                      4-Stage Multi-Tier Patch Validation Pipeline                      │
 ├────────────────────────────┬────────────────────────────┬──────────────────────────────┤
 │ Stage 1: Syntax Validation │ Stage 2: AST Scope Enclosure│ Stage 3: Dynamic PoC Neutral │
 ├────────────────────────────┴────────────────────────────┴──────────────────────────────┤
 │ Stage 4: Clean AST Security Re-scan (Zero New Vulnerabilities Introduced)              │
 └──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │ (Composite Score >= 80/100)
                                            ▼
                           ┌─────────────────────────────────┐
                           │  Automated GitHub Pull Request  │
                           │  (Scorecard Matrix + Diff Audit)│
                           └─────────────────────────────────┘
```

---

## ⚡ Key Highlights & Innovations

1. **Deterministic AST Scans**: Tree-sitter C-bindings traversals for Python & JavaScript with sub-millisecond execution (0.82 ms/case) and 0% false-positive rate on safe parameterized code.
2. **Zero-Trust PoC Sandboxing**: Ephemeral Docker containers isolated with `--cap-drop=ALL`, read-only root filesystems, memory/CPU cgroup bounds, and `--network none` egress blocking.
3. **Targeted Minimal Patching**: Encloses changes strictly inside enclosing AST function scopes, completely avoiding whole-file rewrites and production regression risks.
4. **4-Stage Automated Scorecard**: Validates syntax correctness, AST scope integrity, dynamic exploit neutralization, and re-scan cleanliness before opening GitHub Pull Requests.
5. **Real-Time Telemetry**: Live Server-Sent Events (SSE) and WebSockets streaming compilation, container stdout/stderr, and LLM synthesis directly to the React UI terminal.

---

## 📊 50-Case Empirical Benchmark

| Metric | Target Goal | Achieved Result | Evaluation Status |
| :--- | :--- | :--- | :--- |
| **Total Test Cases** | 50 Cases | **50 Cases** |  Complete |
| **Detection Precision** | $\ge 95.0\%$ | **100.0%** |  Exceeded |
| **Detection Recall** | $\ge 90.0\%$ | **100.0%** |  Exceeded |
| **F1-Score** | $\ge 92.0\%$ | **100.0%** |  Exceeded |
| **False-Positive Rate** | $\le 5.0\%$ | **0.0% (0 / 17 Safe Cases)** |  Zero False Positives |
| **Avg AST Scan Latency** | $\le 50.0\text{ ms}$ | **0.82 ms / case** |  Sub-millisecond |

---

## 🚀 Quickstart Guide

For a full step-by-step operations runbook with UI walkthroughs, CLI instructions, and troubleshooting tips, see the **[Complete User Manual (USER_MANUAL.md)](USER_MANUAL.md)**.

### Prerequisites
- **Python**: 3.12+
- **Node.js**: 20+ & npm
- **Docker & Docker Compose**
- **Ollama**: Running with `qwen2.5-coder:1.5b` (`ollama pull qwen2.5-coder:1.5b`)

---

### Step-by-Step Multi-Terminal Startup

#### 1. Launch Infrastructure (PostgreSQL 16 & Redis 7)
```powershell
docker-compose up -d postgres redis
```

#### 2. Start FastAPI Backend API
```powershell
# Windows:
$env:PYTHONPATH = "backend;."
& .\.venv\Scripts\uvicorn.exe app.main:app --host 0.0.0.0 --port 8000 --reload

# Linux/macOS:
export PYTHONPATH="backend:."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 3. Start Celery Asynchronous Worker
```powershell
# Windows (Requires --pool=solo):
$env:PYTHONPATH = "backend;."
& .\.venv\Scripts\celery.exe -A app.worker.celery_app.celery_app worker --loglevel=info -Q scans,verification,remediation --pool=solo

# Linux/macOS:
export PYTHONPATH="backend:."
celery -A app.worker.celery_app.celery_app worker --loglevel=info -Q scans,verification,remediation
```

#### 4. Start React Frontend Dashboard
```powershell
# Windows:
cd frontend
& "C:\Program Files\nodejs\npm.cmd" run dev

# Linux/macOS:
cd frontend
npm run dev
```
Navigate to **`http://localhost:3000`** to access the live dashboard.

---

## 🛠️ CLI Operations (`patchforge-cli`)

PatchForge AI can be operated headlessly via its command-line interface:

```powershell
# Scan a repository / directory for AST security flaws:
python cli/patchforge.py scan "C:\path\to\your\project"

# Run end-to-end autonomous scan, PoC verification, and patch synthesis:
python cli/patchforge.py e2e "C:\path\to\your\project"
```

---

## 🔒 Security & STRIDE Threat Model

PatchForge AI is engineered from first principles for zero-trust security:
- **Bandit AST Code Scanner**: 0 vulnerabilities identified in `backend/app`.
- **Pip-Audit**: 0 known CVEs across all platform dependencies.
- **Timing Attack Immunity**: HMAC-SHA256 signatures compared via constant-time `hmac.compare_digest`.
- **RBAC**: Multi-tiered role separation (`ADMIN`, `SECURITY_ENGINEER`, `DEVELOPER`, `VIEWER`).

See [`security/threat_model.md`](security/threat_model.md) for full STRIDE threat analysis and [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for production deployment runbooks.

---

## 📄 License
Released under the [MIT License](LICENSE).
