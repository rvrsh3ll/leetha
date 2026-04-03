# Leetha — network host identification engine
# Multi-stage build: compile wheel, then install into slim runtime

# ── Stage 1: Build ──────────────────────────────────────────────
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim AS compile

WORKDIR /src
COPY pyproject.toml uv.lock ./
COPY src/ src/
COPY frontend/dist/ src/leetha/ui/web/dist/

RUN uv build --wheel --out-dir /src/wheels

# ── Stage 2: Runtime ────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="leetha" \
      description="Network host identification and threat surface analysis"

# libpcap required for scapy packet capture
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=compile /src/wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Non-root user for safety
RUN useradd --system --create-home --shell /usr/sbin/nologin appuser
USER appuser

# Persistent storage for fingerprint databases and SQLite
VOLUME /home/appuser/.local/share/leetha
ENV LEETHA_DATA_DIR=/home/appuser/.local/share/leetha

EXPOSE 8080

ENTRYPOINT ["leetha"]
CMD ["--web"]
