FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    curl \
    git \
    jq \
    nmap \
    nodejs \
    npm \
    postgresql-client \
    dnsutils \
    unzip \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://go.dev/dl/go1.23.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.1.linux-amd64.tar.gz && \
    rm go1.23.1.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV CHROME_PATH="/usr/bin/chromium"

RUN go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/tomnomnom/unfurl@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/sensepost/gowitness@latest

RUN go install github.com/hahwul/dalfox/v2@latest

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

RUN nuclei -update-templates -silent || true

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) asset_name="findomain-linux.zip" ;; \
      arm64) asset_name="findomain-aarch64.zip" ;; \
      armhf) asset_name="findomain-armv7.zip" ;; \
      *) echo "Unsupported architecture for Findomain: $arch" >&2; exit 1 ;; \
    esac; \
    findomain_url="$(python3 -c "import json,sys,urllib.request; data=json.load(urllib.request.urlopen('https://api.github.com/repos/Findomain/Findomain/releases/latest')); asset=next((a for a in data['assets'] if a['name']=='${asset_name}'), None); print(asset['browser_download_url'] if asset else '');")"; \
    test -n "$findomain_url"; \
    curl -fsSL "$findomain_url" -o /tmp/findomain.zip; \
    unzip -q /tmp/findomain.zip -d /tmp/findomain; \
    install "$(find /tmp/findomain -type f -name findomain | head -n 1)" /usr/local/bin/findomain; \
    chmod +x /usr/local/bin/findomain; \
    rm -rf /tmp/findomain /tmp/findomain.zip

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) asset_name="amass_linux_amd64.tar.gz" ;; \
      arm64) asset_name="amass_linux_arm64.tar.gz" ;; \
      armhf) asset_name="amass_linux_armv7.tar.gz" ;; \
      i386) asset_name="amass_linux_386.tar.gz" ;; \
      *) echo "Unsupported architecture for Amass: $arch" >&2; exit 1 ;; \
    esac; \
    amass_url="$(python3 -c "import json,urllib.request; data=json.load(urllib.request.urlopen('https://api.github.com/repos/owasp-amass/amass/releases/latest')); asset=next((a for a in data['assets'] if a['name']=='${asset_name}'), None); print(asset['browser_download_url'] if asset else '')")"; \
    test -n "$amass_url"; \
    curl -fsSL "$amass_url" -o /tmp/amass.tar.gz; \
    mkdir -p /tmp/amass; \
    tar -xzf /tmp/amass.tar.gz -C /tmp/amass; \
    install "$(find /tmp/amass -type f -name amass | head -n 1)" /usr/local/bin/amass; \
    chmod +x /usr/local/bin/amass; \
    rm -rf /tmp/amass /tmp/amass.tar.gz

RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r && \
    pip install --no-cache-dir -r /opt/Sublist3r/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/Sublist3r/sublist3r.py "$@"\n' > /usr/local/bin/sublist3r && \
    chmod +x /usr/local/bin/sublist3r

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY database_schema.sql .
COPY bug_job_taxonomy.py .
COPY continuous_recon.py .
COPY js_analysis.py .
COPY monitor_core.py .
COPY monitor_worker.py .
COPY port_worker.py .
COPY shodan_worker.py .
COPY search_intelligence.py .
COPY search_intel_worker.py .
COPY ffuf_worker.py .
COPY queue_ffuf_scan.py .
COPY dashboard.py .
COPY domain_management.py .
COPY templates ./templates
COPY static ./static
COPY export_review_queue.py .
COPY config.example.yaml ./config.example.yaml

CMD ["python", "continuous_recon.py"]
