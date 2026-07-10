FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

USER 1000
EXPOSE 8000
# One worker so the in-memory demo data and the Prometheus counters are shared
# (multi-worker would split both across processes). Threads keep the JWKS fetch
# from blocking the worker. This is lab teaching material, not a scaled service.
ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:8000", "-w", "1", "--threads", "8", "app:app"]
