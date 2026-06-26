FROM python:3.12-alpine

LABEL org.opencontainers.image.authors="Qonnect-IT <info@qonnect-it.nl>"
LABEL org.opencontainers.image.title="unifi-librenms-discovery"
LABEL org.opencontainers.image.description="LibreNMS helper container for UniFi AP discovery and polling"
LABEL org.opencontainers.image.source="https://github.com/Qonnect-IT/Unifi-to-LibreNMS-detection"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

RUN adduser -D -h /app appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sync.py .

USER appuser

CMD ["python", "/app/sync.py"]
