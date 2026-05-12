# backend/Dockerfile
# Nano EASM — Flask Backend
# Runs under Gunicorn with 3 workers, 120s timeout

FROM python:3.12-slim

# ── System dependencies ──────────────────────────────────────
# nmap: network scanning engine (NmapEngine)
# dnsutils: dig/nslookup for DNS operations
# curl/unzip/wget: for installing nuclei
# git: agent platform's git_read tool runs `git log`, `git show`, etc.
#      against the bind-mounted /repo (Phase 2A)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    curl \
    unzip \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Trust the bind-mounted /repo regardless of its host-side ownership.
# Without this, git complains "fatal: detected dubious ownership" on
# any repo owned by a different uid than the container's runtime user
# — which is the default for docker bind-mounts. Setting safe.directory
# at build time means git_read works as soon as the container starts.
RUN git config --global --add safe.directory /repo

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
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "120", "run:app"]
