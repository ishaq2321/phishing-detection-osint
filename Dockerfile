# PhishGuard backend — FastAPI + XGBoost + spaCy
#
# Build from the repository root (context includes backend/):
#   docker build -t phishguard-api .
#   docker run -p 8000:8000 phishguard-api

FROM python:3.10-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first for layer caching.
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r backend/requirements.txt \
    && pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl

# Application code (includes the trained model artefacts in ml/models/).
COPY backend/ ./backend/

EXPOSE 8000

# Absolute "backend.*" imports require running uvicorn from the repo root.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
