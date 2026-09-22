FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 PII_LOCAL_DEMO=0
ENV PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus
WORKDIR /app
RUN pip install --no-cache-dir uv==0.11.25
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev
RUN useradd --system --uid 10001 --create-home piiapp
USER piiapp
EXPOSE 8090
CMD [".venv/bin/python", "-m", "pii_proxy.serve"]
