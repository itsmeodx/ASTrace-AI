# syntax=docker/dockerfile:1
# ─── Stage 1: Builder ─────────────────────────────────────────────────────────
# Throwaway build stage for Python wheels
FROM python:3.11-slim-bookworm AS builder

# libclang bindings
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        "libclang-14-dev=1:14.0.6-12" \
        "clang-14=1:14.0.6-12" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /install

COPY requirements.txt .

# Cache pip wheels across rebuilds
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install/deps --no-warn-script-location -r requirements.txt

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="ASTrace AI"
LABEL org.opencontainers.image.description="AST-Aware C/C++ AI Security Auditor"
LABEL org.opencontainers.image.source="https://github.com/itsmeodx/ASTrace-AI"

# System headers needed by libclang AST parser to successfully resolve standard functions
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        "libclang1-14=1:14.0.6-12" \
        "libclang-common-14-dev=1:14.0.6-12" \
        "libc6-dev=2.36-9+deb12u13" \
    && rm -rf /var/lib/apt/lists/*

# ── libclang discovery path ────────────────────────────────────────────────────
# Consumed by find_libclang() in astrace.py.
ENV CLANG_LIBRARY_PATH=/usr/lib/llvm-14/lib/libclang.so.1

# ── Bring in Python deps from builder ─────────────────────────────────────────
COPY --from=builder /install/deps /usr/local

# ── Non-root user for least-privilege execution ────────────────────────────────
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /app
RUN chown appuser:appuser /app
USER appuser

# ── Application code ───────────────────────────────────────────────────────────
# Note: .env is intentionally omitted and injected at runtime
COPY --chown=appuser:appuser astrace.py .

# CMD injected dynamically via astrace.sh
