FROM aquasec/trivy:0.65.0 AS trivy
FROM python:3.12-slim

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir docker==7.1.0 flask==3.1.1 prometheus-client==0.22.1

WORKDIR /app
COPY watcher.py /app/watcher.py

EXPOSE 8090 8086
CMD ["python", "/app/watcher.py"]
