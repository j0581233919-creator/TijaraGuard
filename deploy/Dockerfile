FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TIJARAGUARD_HOST=0.0.0.0 \
    TIJARAGUARD_PORT=8080 \
    TIJARAGUARD_STATE_DIR=/var/lib/tijaraguard \
    TIJARAGUARD_CATALOG_PATH=/app/examples/catalog.json

RUN useradd --system --create-home --uid 10001 tijaraguard \
    && mkdir -p /app /var/lib/tijaraguard \
    && chown -R tijaraguard:tijaraguard /var/lib/tijaraguard

WORKDIR /app
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./
COPY tijaraguard ./tijaraguard
COPY examples ./examples

RUN pip install --no-cache-dir --no-deps .

USER tijaraguard
EXPOSE 8080
VOLUME ["/var/lib/tijaraguard"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python3 -B -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"

ENTRYPOINT ["python3", "-B", "-m", "tijaraguard", "serve"]
