FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/root/.cache/huggingface \
    TRANSFORMERS_CACHE=/root/.cache/huggingface/hub

WORKDIR /app

# curl for scripts/download_data.sh, git for pip VCS installs. No compiler: every dependency
# ships a prebuilt wheel for linux amd64 and arm64.
# apt over HTTPS: plain-HTTP mirror traffic stalls inside Docker Desktop's VM on macOS.
RUN sed -i 's#http://#https://#g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer cache)
COPY pyproject.toml ./
# CPU-only torch first: the default PyPI wheel drags in several GB of CUDA libraries,
# which no container here can use (Docker on macOS has no GPU passthrough).
RUN pip install --upgrade pip setuptools wheel \
    && pip install torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install -e ".[dev,security]"

# Copy source last (changes most often, invalidates cache least)
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY main.py config.yaml ./

# Gateway listens on an uncommon port (overridable via config.yaml / GUARD_LISTEN_PORT).
EXPOSE 33707
EXPOSE 8000

# Default command: run the LLM Guard Gateway (reads config.yaml for host/port).
# Override with `docker compose run` for one-shot tasks, or the `api` service for the bare detector.
CMD ["python", "main.py"]
