# syntax=docker/dockerfile:1
# ─── Stage 1: Builder ─────────────────────────────────────────────────────────
# Install system libs and Python wheels in a throwaway stage so that build
# tools (gcc, headers, apt cache) never land in the final image.
FROM python:3.11-slim-bookworm AS builder

# Install only what's needed to compile the Python dependencies.
# libclang-14-dev provides the shared library we wrap via the `clang` binding.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        "libclang-14-dev=1:14.0.6-12" \
        "clang-14=1:14.0.6-12" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /install

COPY requirements.txt .

# BuildKit cache mount keeps the pip wheel cache across rebuilds → fast re-installs.
# --no-cache-dir is intentionally OMITTED here; we rely on the mount instead.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install/deps --no-warn-script-location -r requirements.txt

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="ASTrace AI"
LABEL org.opencontainers.image.description="AST-Aware C/C++ AI Security Auditor"
LABEL org.opencontainers.image.source="https://github.com/yourorg/astrace"

# Only copy the runtime .so – no headers, no compiler toolchain.
# libc6-dev   → system headers (stdio.h, stdlib.h …) so libclang can resolve
#               malloc/free/strcpy as CALL_EXPR nodes during AST parsing.
# libclang-common-14-dev → clang built-in headers (stdint.h, stddef.h …)
#               needed for the -resource-dir passed to the parser.
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
# .env is intentionally NOT copied here – it is injected at runtime via
# compose.yaml's `env_file` directive so secrets never land in the image layer.
COPY --chown=appuser:appuser astrace.py .

# No CMD – injected dynamically by audit.sh via `docker compose run`.
