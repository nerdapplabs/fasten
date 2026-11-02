# Python integration smoke. Build context = fasten repo root.
FROM python:3.10-slim

WORKDIR /app

# fasten from local source, plus structlog for the shim test.
COPY python/ /app/sdk/
RUN pip install --no-cache-dir /app/sdk "structlog>=21.5"

# Copy smoke
COPY tests/integration/python/smoke.py /app/smoke.py

ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/smoke.py"]
