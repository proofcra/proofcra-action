# syntax=docker/dockerfile:1.7
# Standalone Self-Contained Dockerfile for GitHub Marketplace (proofcra/proofcra-action)

FROM ghcr.io/anchore/syft:latest AS syft-stage

FROM python:3.12-slim

ARG TARGETARCH=amd64
ARG OSV_SCANNER_VERSION=v2.7.1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PROOFCRA_CACHE_DIR=/tmp/proofcra-cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=syft-stage /syft /usr/local/bin/syft

RUN curl -fsSL \
      "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}" \
      -o /usr/local/bin/osv-scanner \
    && chmod 0755 /usr/local/bin/osv-scanner /usr/local/bin/syft \
    && syft version \
    && osv-scanner --version

WORKDIR /app

COPY src/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/models.py src/feeds.py src/reachability.py src/scanner.py src/sandbox_verify.py src/action_entrypoint.py /app/

RUN mkdir -p /tmp/proofcra-cache && chmod 0777 /tmp/proofcra-cache

ENTRYPOINT ["python", "/app/action_entrypoint.py"]
