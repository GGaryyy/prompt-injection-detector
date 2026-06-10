FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/root/.cache/huggingface \
    TRANSFORMERS_CACHE=/root/.cache/huggingface/hub

WORKDIR /app

# System deps for building wheels (sentence-transformers / torch sometimes need it)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer cache)
COPY pyproject.toml ./
RUN pip install --upgrade pip setuptools wheel \
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
