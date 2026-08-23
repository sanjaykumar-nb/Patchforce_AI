---
title: PatchForge Ollama
emoji: 🤖
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
---

# PatchForge AI - Ollama Inference Backend

Standalone Ollama server running `qwen2.5-coder:1.5b`, baked into the image at
build time. This Space exists purely to serve `OLLAMA_BASE_URL` for the
PatchForge AI backend (deployed separately on Render) - it has no UI of its
own; every route just proxies straight to Ollama's API
(e.g. `https://<this-space-url>/api/generate`, `/api/tags`).
