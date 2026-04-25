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

EXPOSE 8000

# Default command: serve the API. Override with `docker compose run` for one-shot tasks.
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
