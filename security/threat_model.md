# PatchForge AI — Formal STRIDE Threat Model & Security Architecture

---

## 1. Executive Summary

PatchForge AI is an autonomous AST-driven vulnerability detection and remediation platform. Because it operates on untrusted external source code, executes dynamic exploit Proof-of-Concepts (PoCs), and invokes Code LLMs to synthesize production software patches, robust multi-layer defense-in-depth is non-negotiable.

This document establishes the formal **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) threat model for the platform and documents active mitigations.

---

## 2. Threat Analysis & Mitigations Matrix (STRIDE)

| Threat Category | Potential Attack Vector | Impact | Active Mitigation in PatchForge AI |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged GitHub webhook push payload | Malicious scan trigger / false repo ingestion | `hmac.compare_digest` with constant-time verification using repository webhook secret (`backend/app/webhooks/verifier.py`). |
| **Spoofing** | Forged JWT access token | Unauthorized API access | HMAC-SHA256 JWT signature verification with cryptographic secret and expiration enforcement (`backend/app/core/security.py`). |
| **Tampering** | LLM hallucinating out-of-scope code deletions | Production outage / regression | 4-Stage AST validation pipeline verifying syntax, scope enclosure, and single-function boundaries (`backend/app/validation/validator.py`). |
| **Tampering** | Arbitrary file overwrite via directory traversal in clone | Host filesystem corruption | Path containment validation & isolated temporary directories (`tempfile.mkdtemp`). |
| **Repudiation** | Operator denies initiating scan or patch | Loss of auditability | Structured JSON logging with propagated Correlation IDs (`request_id`, `pipeline_id`) and immutable Git commits with signed PR metadata. |
| **Information Disclosure** | Dynamic PoC exfiltrating AWS/database secrets | Credential leakage | Isolated Docker Sandbox running with `--network none` (complete network isolation) and masked environment variables. |
| **Information Disclosure** | LLM prompt injection extracting internal system instructions | System prompt leak | Strict multi-line delimiters (`<<<CODE_DELIMITER_START>>>`) and JSON schema validation (`backend/app/llm/prompts.py`). |
| **Denial of Service** | Malicious AST explosion / infinite loop fixture | CPU / Memory starvation | Sandboxed execution enforces 15-second process timeouts and Docker cgroup limits (`--memory=512m`, `--cpus=1.0`). |
| **Elevation of Privilege** | Container escape during dynamic PoC execution | Host root takeover | Hardened Docker security profile: `cap_drop=["ALL"]`, `read_only=True`, non-root user `appuser` (UID 10001), `no-new-privileges:true`. |
| **Elevation of Privilege** | Low-privilege user modifying security rules | Unauthorized policy change | Role-Based Access Control (`ADMIN`, `SECURITY_ENGINEER`, `DEVELOPER`, `VIEWER`) via FastAPI dependency injection (`backend/app/core/deps.py`). |

---

## 3. Sandboxing & Isolation Guarantees

```
┌─────────────────────────────────────────────────────────────┐
│ Docker Ephemeral Execution Sandbox                         │
├─────────────────────────────────────────────────────────────┤
│ 1. Ephemeral Container Lifecycle: Container destroyed on exit│
│ 2. Security Capabilities: --cap-drop=ALL (Zero Linux caps)  │
│ 3. Filesystem Hardening: Read-only rootfs, tmpfs /tmp       │
│ 4. Network Isolation: --network none (No egress / ingress)  │
│ 5. User Hardening: Non-root UID 10001 (appuser)             │
│ 6. Resource Limits: Memory limit 512MB, CPU limit 1.0 core  │
│ 7. Process Execution: Strict 15.0s subprocess timeout       │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Cryptographic Standards

- **Password Storage**: Bcrypt with work factor 12 (`bcrypt.gensalt(12)`).
- **Session Tokens**: HMAC-SHA256 JWT tokens with 120-minute expiration.
- **Webhook Authenticity**: HMAC-SHA256 signatures validated via `hmac.compare_digest` to prevent side-channel timing attacks.
