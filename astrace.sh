#!/usr/bin/env bash
# ─── ASTrace AI – Runner Script ─────────────────────────────────────────────────
# Usage:  ./audit.sh <path/to/file.c>
# Orchestrates Docker/local execution and dependency provisioning.
# Requirements: bash >=4.0, docker (with Compose v2), realpath (coreutils)
# ShellCheck: https://www.shellcheck.net/  (target: SC2034, SC2086, SC2155, …)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly CONTAINER_SRC_DIR="/app/external_src"

# ── Colour codes ───────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  CLR_CYAN='\033[0;36m'
  CLR_BOLD='\033[1m'
  CLR_RED='\033[0;31m'
  CLR_YELLOW='\033[0;33m'
  CLR_RESET='\033[0m'
else
  CLR_CYAN='' CLR_BOLD='' CLR_RED='' CLR_YELLOW='' CLR_RESET=''
fi

# ── Logging helpers ───────────────────────────────────────────────────────────
log_info()  { printf "${CLR_CYAN}${CLR_BOLD}[astrace-ai]${CLR_RESET}  %b\n" "$*"; }
log_warn()  { printf "${CLR_YELLOW}${CLR_BOLD}[warn]${CLR_RESET}  %b\n" "$*" >&2; }
log_error() { printf "${CLR_RED}${CLR_BOLD}[error]${CLR_RESET}  %b\n" "$*" >&2; }

spin() {
  local pid=$1
  local delay=0.15
  local spinstr='|/-\'
  while kill -0 "$pid" 2>/dev/null; do
    local temp="${spinstr#?}"
    printf " [%c] " "$spinstr"
    local spinstr="${temp}${spinstr%"$temp"}"
    sleep $delay
    printf "\b\b\b\b\b"
  done
  printf "     \b\b\b\b\b"
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  printf "Usage:  %s [--local] [options] <path/to/file.c>\n" "$(basename "$0")" >&2
  printf "  --local : Run directly on the host using .venv (bypasses Docker)\n" >&2
  printf "  --check : Run environment diagnostic check\n" >&2
  printf "  --version : Show version information\n" >&2
  exit 1
}

# ── Pre-flight: argument count ────────────────────────────────────────────────
[[ $# -ge 1 ]] || usage

RUN_LOCAL=0
# Detect if we should run locally (either --local is passed, or we are running a check/version)
if [[ $* == *"--local"* ]] || [[ $* == *"--check"* ]] || [[ $* == *"--version"* ]]; then
  RUN_LOCAL=1
fi

# Strip --local from args so it doesn't confuse the python script (if it survives)
# But actually, we can just pass them all through since astrace.sh handles its own.
# To be clean, we'll only shift --local if it was the FIRST argument to maintain backward compatibility.
if [[ "${1:-}" == "--local" ]]; then
  shift
fi

# POSIX standard end-of-options marker
if [[ "${1:-}" == "--" ]]; then
  shift
fi

# ── Pre-flight: resolve absolute path (only if a file is provided) ──
ABSOLUTE_PATH=""
SOURCE_DIR=""
SOURCE_FILE=""

# If there's an argument left and it's not a known flag, treat it as a file.
# We also SKIP this if --check or --version is present anywhere in the args.
if [[ $* == *"--check"* ]] || [[ $* == *"--version"* ]]; then
  : # Skip file check
elif [[ $# -gt 0 ]] && [[ "$1" != --* ]]; then
  TARGET_INPUT="$1"
  if ! ABSOLUTE_PATH="$(realpath -- "$TARGET_INPUT" 2>/dev/null)"; then
    log_error "Cannot resolve path: ${TARGET_INPUT}"
    exit 1
  fi

  if [[ ! -f "$ABSOLUTE_PATH" ]]; then
    log_error "File not found: ${ABSOLUTE_PATH}"
    exit 1
  fi

  SOURCE_DIR="$(dirname "$ABSOLUTE_PATH")"
  SOURCE_FILE="$(basename "$ABSOLUTE_PATH")"
fi

# Reject directories
if [[ -d "$ABSOLUTE_PATH" ]]; then
  log_error "Expected a file, got a directory: ${ABSOLUTE_PATH}"
  exit 1
fi


# ── Pre-flight: Docker availability ──────────────────────────────────────────
if [[ $RUN_LOCAL -eq 0 ]]; then
  if ! command -v docker &>/dev/null; then
    log_error "Docker is not installed or not in PATH."
    exit 1
  fi

  if ! docker compose version &>/dev/null; then
    log_error "Docker Compose v2 ('docker compose') is required but not available."
    log_warn  "Install it from: https://docs.docker.com/compose/install/"
    exit 1
  fi
fi

# ── Pre-flight: .env file ─────────────────────────────────────────────────────
if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
  if [[ -f "${SCRIPT_DIR}/.env.example" ]]; then
    log_warn ".env not found – copying from .env.example"
    cp -- "${SCRIPT_DIR}/.env.example" "${SCRIPT_DIR}/.env"
    log_warn "Please edit ${SCRIPT_DIR}/.env and set your API key, then re-run."
  else
    log_error "No .env found. Create one from .env.example."
  fi
  exit 1
fi

if [[ $RUN_LOCAL -eq 1 ]]; then
  [[ -n "$SOURCE_FILE" ]] && log_info "Auditing locally: ${CLR_BOLD}${SOURCE_FILE}${CLR_RESET}"

  if [[ ! -f "${SCRIPT_DIR}/.venv/bin/python" ]]; then
    log_info "Creating .venv..."
    python3 -m venv "${SCRIPT_DIR}/.venv"
    "${SCRIPT_DIR}/.venv/bin/pip" install --quiet -r "${SCRIPT_DIR}/requirements.txt"
  fi
  exec "${SCRIPT_DIR}/.venv/bin/python" "${SCRIPT_DIR}/astrace.py" "$@"
else
  # ── Docker Execution ──────────────────────────────────────────────────────────
  printf "${CLR_CYAN}${CLR_BOLD}[astrace-ai]${CLR_RESET}  Building Docker image..."
  DOCKER_BUILDKIT=1 docker compose build --quiet audit > "${SCRIPT_DIR}/.docker-build.log" 2>&1 &
  spin $!
  if ! wait $!; then
    printf " ${CLR_RED}FAILED${CLR_RESET}\n"
    log_error "Docker build failed. See ${SCRIPT_DIR}/.docker-build.log for details."
    exit 1
  fi
  printf " ${CLR_CYAN}DONE${CLR_RESET}\n"

  [[ -n "$SOURCE_FILE" ]] && log_info "Auditing: ${CLR_BOLD}${SOURCE_FILE}${CLR_RESET}\n"

  # Translate host path to container path if needed
  args=()
  for arg in "$@"; do
    [[ "$arg" == "$ABSOLUTE_PATH" || "$arg" == "$TARGET_INPUT" ]] && arg="${CONTAINER_SRC_DIR}/${SOURCE_FILE}"
    args+=("$arg")
  done

  VOL_ARG=()
  [[ -n "$SOURCE_DIR" ]] && VOL_ARG=("--volume" "${SOURCE_DIR}:${CONTAINER_SRC_DIR}:ro")

  exec env COMPOSE_PROGRESS=quiet docker compose \
    run --rm "${VOL_ARG[@]}" audit python astrace.py "${args[@]}"
fi
