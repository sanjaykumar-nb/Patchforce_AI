# Hugging Face Space - Ollama inference server for PatchForge AI
# ================================================================
# The model is pulled at BUILD time (not container start) and baked into the
# image layer. Hugging Face's free Spaces tier has no persistent storage, so
# without this every sleep/wake cycle would re-download the ~1GB model from
# scratch on the next request - baking it in means only the container itself
# needs to restart, not the download.

FROM ollama/ollama:latest

# Hugging Face's Docker Spaces proxy the public URL straight to this port
# (declared in README.md's `app_port`). Pointing Ollama at it directly avoids
# needing a separate reverse proxy inside the container.
ENV OLLAMA_HOST=0.0.0.0:7860
ENV OLLAMA_MODELS=/models

RUN mkdir -p /models

# Start the server just long enough to pull the model, then stop it - this is
# the standard pattern for baking an Ollama model into a Docker image.
RUN (ollama serve &) && \
    sleep 5 && \
    ollama pull qwen2.5-coder:1.5b && \
    pkill ollama

EXPOSE 7860

CMD ["ollama", "serve"]
