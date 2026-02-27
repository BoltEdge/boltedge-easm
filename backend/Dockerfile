# backend/Dockerfile
# BoltEdge EASM — Flask Backend
# Runs under Gunicorn with 3 workers, 120s timeout

FROM python:3.12-slim

# ── System dependencies ──────────────────────────────────────
# nmap: network scanning engine (NmapEngine)
# dnsutils: dig/nslookup for DNS operations
# curl/unzip/wget: for installing nuclei
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    curl \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# ── Install Nuclei (ProjectDiscovery) ────────────────────────
# Vulnerability scanner used by NucleiEngine
ARG NUCLEI_VERSION=3.3.7
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# Download default nuclei templates
RUN nuclei -update-templates -silent || true

# ── Python dependencies ──────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ─────────────────────────────────────────
COPY . .

# ── Writable temp directory for report generation ────────────
RUN mkdir -p /tmp/easm-reports && chmod 777 /tmp/easm-reports

# ── Expose port ──────────────────────────────────────────────
EXPOSE 5000

# ── Run with Gunicorn ────────────────────────────────────────
# --preload: create_app() runs once in master (scheduler guard)
# --workers 3: matches handover doc recommendation
# --timeout 120: accommodates long-running scan operations
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "--timeout", "120", "--preload", "run:app"]
