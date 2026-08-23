# PatchForge AI — Complete User Manual & Operations Guide

---

## 📖 Table of Contents
1. [Overview & Quick Reference](#1-overview--quick-reference)
2. [Prerequisites & System Startup](#2-prerequisites--system-startup)
3. [Using the Web Dashboard UI](#3-using-the-web-dashboard-ui)
4. [Using the Interactive CLI (`patchforge-cli`)](#4-using-the-interactive-cli)
5. [Testing with Real Repositories](#5-testing-with-real-repositories)
6. [Setting Up GitHub Webhooks for Automated CI/CD](#6-setting-up-github-webhooks)
7. [Database Management & Maintenance](#7-database-management)
8. [Troubleshooting & FAQ](#8-troubleshooting--faq)

---

## 1. Overview & Quick Reference

**PatchForge AI** is an autonomous DevSecOps platform that executes a 5-step closed-loop security remediation workflow:

```
[ Code Repository ] 
       │
       ▼ (1) Tree-sitter AST Static Scan
[ AST Findings ] 
       │
       ▼ (2) Dynamic Docker Sandbox PoC Verification
[ Confirmed Exploits ] 
       │
       ▼ (3) Local LLM AST-Targeted Patch Synthesis
[ Candidate Patch ] 
       │
       ▼ (4) 4-Stage Multi-Tier Validation Gate
[ Validated Patch ] 
       │
       ▼ (5) Automated Scored GitHub Pull Request
[ Fixed Code in Production ]
```

---

## 2. Prerequisites & System Startup

### Prerequisites Checklist
- **Python**: Version 3.12 or higher.
- **Node.js**: Version 20 or higher.
- **Docker**: Docker Desktop (or Linux Docker daemon) running.
- **Ollama**: Running locally with `qwen2.5-coder:1.5b` or `7b`:
  ```bash
  ollama pull qwen2.5-coder:1.5b
  ollama run qwen2.5-coder:1.5b
  ```

---

### Step-by-Step Multi-Terminal Startup

#### Terminal 1: PostgreSQL & Redis (Infrastructure)
```powershell
# From project root:
docker-compose up -d postgres redis
```

#### Terminal 2: FastAPI Backend Engine
```powershell
# Windows PowerShell:
$env:PYTHONPATH = "backend;."
& .\.venv\Scripts\uvicorn.exe app.main:app --host 0.0.0.0 --port 8000 --reload

# Linux / macOS:
export PYTHONPATH="backend:."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*API is accessible at `http://localhost:8000` (Swagger docs at `http://localhost:8000/docs`).*

#### Terminal 3: Celery Background Task Worker
```powershell
# Windows PowerShell (use --pool=solo on Windows):
$env:PYTHONPATH = "backend;."
& .\.venv\Scripts\celery.exe -A app.worker.celery_app.celery_app worker --loglevel=info -Q scans,verification,remediation --pool=solo

# Linux / macOS:
export PYTHONPATH="backend:."
celery -A app.worker.celery_app.celery_app worker --loglevel=info -Q scans,verification,remediation
```

#### Terminal 4: React Cyber Dashboard (Vite SPA)
```powershell
# Windows PowerShell:
cd frontend
& "C:\Program Files\nodejs\npm.cmd" run dev

# Linux / macOS:
cd frontend
npm run dev
```
*Dashboard is accessible in your browser at `http://localhost:3000`.*

---

## 3. Using the Web Dashboard UI

The web interface is organized into 5 intuitive sections:

### 1. 📊 Dashboard Tab (`DashboardOverview.jsx`)
- **Telemetry Cards**: Live count of Monitored Repositories, Detected Flaws, Sandbox Verified PoCs, and Synthesized Patches.
- **Severity Distribution Bar**: Interactive visual breakdown of Critical, High, Medium, and Low findings.
- **Recent Remediation Activity**: Real-time status feed of ongoing scans and validations.

### 2. 🛡️ Vulnerabilities Tab (`VulnerabilityTable.jsx`)
- **Search & Filters**: Search by CWE, Rule ID, file path, or function name. Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **AST Context**: Shows the exact code snippet and enclosing function scope identified by Tree-sitter.
- **Verify PoC (Cyan Flask Button)**: Launches an isolated Docker container to dynamically prove exploitability.
- **Remediate (Purple Wrench Button)**: Synthesizes a minimal function patch via the local LLM and runs all 4 validation gates.

### 3. 📁 Repositories Tab (`RepositoriesView.jsx`)
- **Connect Repository**: Click `+ Connect Repository` to register a local directory or remote GitHub repo.
- **Scan Now (Play Button)**: Triggers an immediate AST traversal scan.
- **Delete (Trash Button)**: Deletes the repository and cleans up its database records.

### 4. 🔀 Pull Requests Tab (`PullRequestsView.jsx`)
- Displays all automated GitHub Pull Requests created by PatchForge AI with diff previews and validation scorecard summaries.

### 5. 💻 Live Logs Tab (`LiveLogTerminal.jsx`)
- Real-time Server-Sent Events (SSE) streaming terminal displaying AST traversals, sandbox container stdout/stderr, and LLM synthesis tokens.

---

## 4. Using the Interactive CLI (`patchforge-cli`)

PatchForge AI includes a command-line interface for local and headless operations:

```powershell
$env:PYTHONPATH = "backend;."
```

### 1. Scan a Project Directory
```powershell
.venv\Scripts\python.exe cli\patchforge.py scan "C:\path\to\your\project"
```
*Outputs a color-coded table of all detected CWE vulnerabilities with line numbers and functions.*

### 2. Dynamically Verify Exploits
```powershell
.venv\Scripts\python.exe cli\patchforge.py verify --vuln-id <VULN_UUID>
```

### 3. Synthesize & Validate Patch
```powershell
.venv\Scripts\python.exe cli\patchforge.py remediate "C:\path\to\your\project" --vuln-id <VULN_UUID>
```

### 4. End-to-End Autonomous Pipeline
```powershell
.venv\Scripts\python.exe cli\patchforge.py e2e "C:\path\to\your\project"
```

---

## 5. Testing with Real Repositories

### Step-by-Step Guide for Real Codebases:

1. **Via Web Dashboard**:
   - Go to `http://localhost:3000` > **Repositories** tab.
   - Click **`+ Connect Repository`**.
   - Input:
     - **Repository Name**: e.g., `ai-classifier`
     - **Full Name**: e.g., `Gurumurthys1/Building-an-AI-Classifier-Identifying-Cats-Dogs-Pandas-with-PyTorch`
     - **Clone URL**: `https://github.com/Gurumurthys1/Building-an-AI-Classifier-Identifying-Cats-Dogs-Pandas-with-PyTorch.git` (or a local path like `C:\projects\my-app`)
     - **Language**: `python`
   - Click **"Save Repository"**.
   - Click **"Scan Now"** (`Play` button).

2. **Review & Remediate**:
   - Switch to the **Vulnerabilities** tab.
   - Click **"Remediate"** on any finding.
   - The LLM will generate a targeted diff and validate it across the 4 quality gates.
   - Click **"Create GitHub PR"** to dispatch the pull request to your GitHub repository!

---

## 6. Setting Up GitHub Webhooks for Automated CI/CD

To enable autonomous scans whenever developers push code:

1. Open your repository on GitHub > **Settings > Webhooks > Add webhook**.
2. **Payload URL**: `http://<your-server-ip>:8000/api/v1/webhooks/github`
3. **Content type**: `application/json`
4. **Secret**: `patchforge_webhook_secret_hmac_256` (configured in `.env`)
5. **Events**: Select **"Just the push event"**.
6. Click **Add webhook**.

*On every `git push`, PatchForge AI automatically verifies the HMAC-SHA256 signature, executes the AST scan, verifies any exploits, and opens remediation PRs.*

---

## 7. Database Management & Maintenance

### 1. View Database Record Counts
```powershell
$env:PYTHONPATH = "backend;."
.venv\Scripts\python.exe -c "from app.database import SessionLocal; from app.models import Repository, Scan, Vulnerability, Patch; db = SessionLocal(); print(f'Repos: {db.query(Repository).count()}, Scans: {db.query(Scan).count()}, Vulns: {db.query(Vulnerability).count()}'); db.close()"
```

### 2. Reset / Purge Test Records
```powershell
$env:PYTHONPATH = "backend;."
.venv\Scripts\python.exe -c "from app.database import SessionLocal; from app.models import Repository, Scan, Vulnerability, Patch, ExploitVerification, ASTNode; db = SessionLocal(); [db.delete(x) for x in db.query(Repository).filter(Repository.name.like('test-%')).all()]; db.commit(); print('Cleaned!'); db.close()"
```

---

## 8. Troubleshooting & FAQ

### Q1: `uvicorn.exe : The module '.venv' could not be loaded`
- **Fix**: Run from the project root using the call operator `&`:
  ```powershell
  cd C:\Users\acer\OneDrive\Desktop\Patchforge_AI
  & .\.venv\Scripts\uvicorn.exe app.main:app --host 0.0.0.0 --port 8000 --reload
  ```

### Q2: Celery shows `[WinError 5] Access is denied` on Windows
- **Fix**: Celery requires single-process mode on Windows. Add `--pool=solo`:
  ```powershell
  & .\.venv\Scripts\celery.exe -A app.worker.celery_app.celery_app worker --loglevel=info -Q scans,verification,remediation --pool=solo
  ```

### Q3: `npm : File npm.ps1 cannot be loaded because running scripts is disabled`
- **Fix**: Use `npm.cmd` directly:
  ```powershell
  & "C:\Program Files\nodejs\npm.cmd" run dev
  ```

### Q4: Ollama connection refused
- **Fix**: Ensure Ollama is running in background (`ollama serve` or open Ollama desktop app). Test with:
  ```powershell
  curl http://localhost:11434/api/tags
  ```
