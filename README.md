# PatchForge AI

**Find a vulnerability, check that it's exploitable, generate a minimal fix, validate the fix, and open a pull request — without a human writing the patch.**

PatchForge AI scans Python and JavaScript code using syntax trees (not regex), confirms findings with a proof-of-concept exploit, asks an LLM to rewrite only the vulnerable function, validates the result in four stages, and opens a GitHub pull request with a scorecard attached.

- **Live frontend:** https://patchforgeai.vercel.app
- **Live API:** https://patchforge-ai-v7ro.onrender.com/api/v1/health
- **Stack:** FastAPI · SQLAlchemy/Alembic · PostgreSQL (Neon) · Tree-sitter · Groq (`openai/gpt-oss-20b`) · React 18 + Vite

> This is a hackathon project. The pipeline works end to end, but read [Known limitations](#known-limitations) before trusting it on real code.

---

## How it works

```text
 GitHub repo ──► 1. Scan ──► 2. Verify ──► 3. Patch ──► 4. Validate ──► 5. Pull request
                 AST rules    PoC exploit    LLM rewrites   syntax, AST,     branch + commit
                 find the     runs against   only the       PoC re-run,      + scorecard
                 vulnerable   the finding    vulnerable     security         (or a clearly
                 function                    function       re-scan          marked simulation)
```

1. **Scan.** Tree-sitter (JavaScript) and Python's `ast` module (Python) parse each file. Rules walk the tree and record the exact function and line range of each finding.
2. **Verify.** For supported CWEs, a proof-of-concept harness calls the vulnerable function with an exploit payload and reports whether the exploit fired.
3. **Patch.** The LLM receives only the vulnerable function, not the whole file, and returns a replacement. The replacement is spliced back into the original file, so nothing else in the file changes. If the model's output is cut off or missing its return path, it's retried. If the LLM is unavailable, a fixed template patch is used instead.
4. **Validate.** Every patch goes through four checks: it must parse, it must keep the function's structure, the PoC is re-run against the patched code, and the patched file is re-scanned. These combine into a 0–100 score.
5. **Pull request.** The app creates a branch, commits the patched file, and opens a PR with the scorecard. If it can't push (for example, the account has no linked GitHub token), the PR is marked **simulated** in the UI with the reason. It is never shown as a real PR.

---

## What it detects

| Rule | Language | CWE | PoC verification | Automated patch |
| :--- | :--- | :--- | :---: | :---: |
| `PY-SQLI-001` / `JS-SQLI-001` | Python / JS | CWE-89 SQL injection | ✅ | ✅ |
| `PY-CMDI-001` / `JS-CMDI-001` | Python / JS | CWE-78 command injection | ✅ | ✅ |
| `PY-PATH-001` / `JS-PATH-001` | Python / JS | CWE-22 path traversal | ✅ | ✅ |
| `PY-DESER-001` | Python | CWE-502 unsafe deserialization | ✅ | ✅ |
| `PY-EVAL-001` | Python | CWE-95 eval injection | — | LLM only |
| `PY-YAML-001` | Python | CWE-20 unsafe `yaml.load` | — | LLM only |
| `PY-SECRET-001` | Python | CWE-798 hardcoded secrets | — | LLM only |
| `PY-HASH-001` | Python | CWE-328 weak hash | — | LLM only |
| `PY-TLS-001` | Python | CWE-295 disabled TLS verification | — | LLM only |

"LLM only" means the rule can be scanned for and the LLM will attempt a fix, but there's no PoC harness or fallback template for it. For those findings, stage 3 of validation can't give a confirmed result.

---

## Evaluation — what we actually measured

### Backend test suite
**70 automated tests pass** (`pytest backend/tests`). They cover authentication and RBAC, scanning, PoC verification, patch generation and splicing, all four validation stages, PR creation, webhooks, and multi-tenant isolation.

### The "50-case benchmark" and why it doesn't show 100% accuracy
`benchmark/benchmark_suite.py` runs 50 cases (33 vulnerable, 17 safe) across CWE-89/78/22/502, and every case passes. **That result should not be read as 100% precision or recall.** The cases are generated from a few templates. Within each CWE, the vulnerable cases are the same snippet with only the function name changed, and so are the safe cases. The rules were written against these same patterns, so the benchmark shows that the scanner still detects the shapes it was designed for. That makes it useful as a **regression check**. It is not an accuracy measurement.

What it doesn't test:
- Real-world code taken from outside the project
- Taint that flows through variables, helper functions, or other modules
- Sanitisers the rules don't know about, which cause false positives
- Unfamiliar sink APIs, ORMs, or query builders, which cause false negatives

**Realistic expectation:** like most pattern-based static analysis, the scanner will produce false positives and miss vulnerabilities on real codebases. We haven't measured either rate on external code yet. Doing that against a labelled public dataset such as OWASP Benchmark, Juliet, or CVE-fix commits is the top item on the roadmap.

The average scan latency the suite reports (under 1 ms per case) was measured on small single-function snippets. Whole-repository scans depend on repo size and are dominated by `git clone`.

---

## Architecture

| Layer | What's there |
| :--- | :--- |
| **Frontend** | React 18 + Vite SPA on Vercel. `/api/*` is proxied to the backend, so the browser never makes cross-origin calls. |
| **API** | FastAPI with JWT auth and role checks (`ADMIN`, `SECURITY_ENGINEER`, `DEVELOPER`, `VIEWER`). Scans run as background tasks and return `202` immediately. Clients poll `GET /scans/{id}`. |
| **Multi-tenancy** | Every user and repository belongs to an organization. Every query for repositories, scans, vulnerabilities, patches, and PRs is filtered by the caller's organization. |
| **Engine** | AST scanner, PoC generator and runner, LLM patch generator (Groq, with an optional local Ollama client), 4-stage validator, GitHub PR client. |
| **Data** | PostgreSQL (Neon). The schema is versioned with Alembic, and migrations run automatically when the container starts. |

Celery and Redis are in the codebase but aren't used by any live request path. Everything runs inside the API process.

---

## Running locally

**Prerequisites:** Python 3.11+, Node 20+, Git, a free [Groq API key](https://console.groq.com).

```bash
cp .env.example .env          # set GROQ_API_KEY, JWT_SECRET, and ADMIN_EMAILS (your email)
pip install -r backend/requirements.txt
cd backend && alembic upgrade head && cd ..
```

```bash
# Backend: run from the repo root so fixtures/ resolves
PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```bash
# Frontend
cd frontend && npm install && npm run dev      # http://localhost:3000
```

```bash
# Tests: run from the repo root, using a throwaway SQLite database
DATABASE_URL=sqlite:///./test_local.db pytest backend/tests --ignore=backend/tests/test_benchmark_suite.py
```

On Windows PowerShell, set environment variables with `$env:NAME = "value"` instead of the `NAME=value` prefix.

### Getting real pull requests
A PR is only pushed to GitHub if a token with `repo` scope is available. You can provide one in either of two ways:
- Sign in using the **GitHub token** tab. Accounts created with a password or OTP have no linked token.
- Set `GITHUB_ACCESS_TOKEN` on the server as a service-level token.

If neither is available, the PR is recorded as **simulated**, and the UI says so.

### Getting an admin account
Self-registration always creates a `DEVELOPER` account, whatever role is requested. To get `ADMIN`, list your email in `ADMIN_EMAILS` before you register.

---

## Security notes

- **Tenant isolation** is enforced at the query layer on every resource endpoint.
- **No self-escalation.** Clients can't choose their role. Elevated roles come only from the `ADMIN_EMAILS` allow-list.
- **Webhook signatures** are checked with HMAC-SHA256 and compared in constant time with `hmac.compare_digest`.
- **OTP codes** come from `secrets` and are returned in API responses only when `DEBUG` is on.
- **GitHub tokens** are per-user. A request never uses another user's token.

See [`security/threat_model.md`](security/threat_model.md) for the STRIDE analysis.

---

## Known limitations

These are real gaps, not planned polish:

1. **PoC execution is not isolated.** The "sandbox" runs exploit harnesses as a local subprocess with a timeout. There's no container, no network isolation, and no dropped capabilities. A Docker runner exists in the code but isn't used for execution. Don't point this at untrusted repositories on a machine you care about.
2. **Detection is pattern-based.** Rules match known sink calls and string-building patterns inside a single function. There's no dataflow or taint tracking across functions or files. See the evaluation section above.
3. **Detection accuracy on real-world code hasn't been measured.**
4. **Patch quality depends on the LLM.** Validation catches broken or unchanged patches, but a patch can still pass all four stages and be semantically wrong, for example if it changes behaviour the PoC doesn't exercise. Every PR needs human review. That's why the output is a PR and not a direct commit.
5. **Free-tier hosting.** The Render instance sleeps after about 15 minutes idle, so the first request after that takes 30–60 seconds. Large repositories may exceed the 512 MB memory limit.
6. **No in-app role management.** The only way to promote users is the `ADMIN_EMAILS` allow-list.

---

## Roadmap

- Evaluate precision and recall against an external labelled dataset (OWASP Benchmark, Juliet, real CVE-fix commits) and publish the numbers, including where it fails
- Intra-file taint tracking so findings follow data from source to sink
- Real container isolation for PoC runs
- More languages (Go, Java) and more CWEs
- In-app role promotion for organization owners

---

## Further docs
- [`USER_MANUAL.md`](USER_MANUAL.md): walkthrough of the UI
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
- [`benchmark/benchmark_report.md`](benchmark/benchmark_report.md): raw output of the regression suite. Read the evaluation section above for how to interpret it.
