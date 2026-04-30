# Python integration smoke. Build context = fasten repo root.
FROM python:3.10-slim

WORKDIR /app

# Install fasten from local source
COPY python/ /app/sdk/
RUN pip install --no-cache-dir /app/sdk

# Copy smoke
COPY tests/integration/python/smoke.py /app/smoke.py

ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/smoke.py"]
