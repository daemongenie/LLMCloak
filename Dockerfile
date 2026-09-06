# =============================================================================
# Dockerfile — LLMCloak (Quantum Sphere EOOD)
#
# Build:  docker build -t llmcloak .
# Run:    docker run -d --name llmcloak -p 8917:8917 -v llmcloak_data:/data llmcloak
#
# First run: open http://localhost:8917/dashboard and set the passphrase
# (mode A, manual unlock) — or start unlocked providing LLMCLOAK_KEY
# (Fernet key, mode B headless).
#
# All secrets/persistent state live in /data (volume). Nothing sensitive
# is baked into the image.
# =============================================================================

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LLMCLOAK_HOST=0.0.0.0 \
    LLMCLOAK_PORT=8917 \
    LLMCLOAK_VAULT=/data/vault.txt \
    LLMCLOAK_CONFIG=/data/service_config.json

WORKDIR /app

# Dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (license + docs shipped for compliance)
COPY service.py core.py dashboard.py vaultctl.py ./
COPY LICENSE README.md INSTALL.md BENCH_REPORT.md CONTRIBUTING.md THIRD_PARTY_NOTICES.md ./
COPY tests ./tests

# Non-root runtime user; /data owned by it so the volume is writable
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin llmcloak \
    && mkdir -p /data \
    && chown -R llmcloak:llmcloak /app /data
USER llmcloak

VOLUME ["/data"]
EXPOSE 8917

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys,os; r=urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('LLMCLOAK_PORT','8917')+'/health', timeout=4); sys.exit(0 if r.status==200 else 1)"

# exec so SIGTERM reaches uvicorn; port follows LLMCLOAK_PORT
CMD ["sh", "-c", "exec python -m uvicorn service:app --host 0.0.0.0 --port ${LLMCLOAK_PORT:-8917} --no-server-header"]
