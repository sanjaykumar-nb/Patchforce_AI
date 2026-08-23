# PatchForge AI — Enterprise Production Deployment Guide

---

## 1. Overview & Architecture

PatchForge AI is designed for cloud-native deployment using Docker Compose, Kubernetes (EKS, GKE, AKS), or bare-metal Linux servers.

```
                  ┌───────────────────────────────┐
                  │    TLS / HTTPS Reverse Proxy  │
                  │       (Nginx / Traefik)       │
                  └──────────────┬────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       [ Frontend (Port 80) ]         [ Backend API (Port 8000) ]
        (Nginx + Vite SPA)             (FastAPI + Uvicorn Workers)
                                                 │
                                 ┌───────────────┴───────────────┐
                                 ▼                               ▼
                       [ PostgreSQL 16 DB ]             [ Redis 7 Broker ]
                                 │                               │
                                 └───────────────┬───────────────┘
                                                 ▼
                                     [ Celery Async Workers ]
                                     (scans, verify, remediate)
                                                 │
                                                 ▼
                                     [ Local / Remote Ollama ]
                                     (qwen2.5-coder:1.5b / 7b)
```

---

## 2. Docker Compose Production Deployment

The root directory includes [`docker-compose.prod.yml`](../docker-compose.prod.yml) which defines the complete multi-container production stack.

### 1. Configure Production Environment Variables
Create `.env.prod`:
```bash
# PostgreSQL Database
POSTGRES_USER=patchforge_admin
POSTGRES_PASSWORD=UltraSecureDBPassword2026!
POSTGRES_DB=patchforge_production

# Redis Broker
REDIS_URL=redis://redis:6379/0

# Security & Cryptography
JWT_SECRET=super_secret_production_jwt_signing_key_at_least_32_bytes_long
GITHUB_WEBHOOK_SECRET=your_github_organization_webhook_hmac_secret_key

# Ollama LLM Inference Endpoint
OLLAMA_BASE_URL=http://host.docker.internal:11434
```

### 2. Build & Launch Production Stack
```bash
docker-compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

### 3. Verify Health Probes
```bash
curl -f http://localhost:8000/health
curl -f http://localhost:8000/ready
curl -f http://localhost:8000/metrics
```

---

## 3. High-Throughput Hardware Recommendations

| Component | Minimum Spec (Dev) | Recommended Production Spec (Enterprise) |
| :--- | :--- | :--- |
| **CPU** | 4 Cores | 16+ Cores (AMD EPYC / Intel Xeon) |
| **RAM** | 8 GB | 32 GB+ ECC Memory |
| **Storage** | 20 GB SSD | 100 GB+ NVMe SSD |
| **GPU (Optional)** | None (CPU inference) | NVIDIA RTX 4090 / A10G / A100 (vLLM / Ollama CUDA) |
