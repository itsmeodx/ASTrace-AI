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
  printf "Usage:  %s [options] <path/to/file.c>\n" "$(basename "$0")" >&2
  printf "  -l, --local   : Run directly on the host using .venv (bypasses Docker)\n" >&2
  printf "  -c, --check   : Run environment diagnostic check\n" >&2
  printf "  -v, --version : Show version information\n" >&2
  exit 1
}

# ── Pre-flight: argument count ────────────────────────────────────────────────
[[ $# -ge 1 ]] || usage

# ── Argument Parsing ──────────────────────────────────────────────────────────
RUN_LOCAL=0
CLI_MODE="audit"  # Default mode
PASSTHROUGH_ARGS=()
SOURCE_FILE_INPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--local)
      RUN_LOCAL=1
      shift
      ;;
    -c|--check)
      CLI_MODE="check"
      RUN_LOCAL=1
      PASSTHROUGH_ARGS+=("--check")
      shift
      ;;
    -v|--version)
      CLI_MODE="version"
      RUN_LOCAL=1
      PASSTHROUGH_ARGS+=("--version")
      shift
      ;;
    --)
      shift
      PASSTHROUGH_ARGS+=("$@")
      break
      ;;
    -*)
      log_error "Unknown option: $1"
      usage
      ;;
    *)
      if [[ -z "$SOURCE_FILE_INPUT" ]]; then
        SOURCE_FILE_INPUT="$1"
      fi
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

# ── Pre-flight Checks ─────────────────────────────────────────────────────────

# Resolve absolute path (only if not doing a check/version without a file)
ABSOLUTE_PATH=""
SOURCE_DIR=""
SOURCE_FILE=""

if [[ -n "$SOURCE_FILE_INPUT" ]]; then
  if ! ABSOLUTE_PATH="$(realpath -- "$SOURCE_FILE_INPUT" 2>/dev/null)"; then
    log_error "Cannot resolve path: ${SOURCE_FILE_INPUT}"
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
  [[ "$CLI_MODE" == "audit" && -n "$SOURCE_FILE" ]] && log_info "Auditing locally: ${CLR_BOLD}${SOURCE_FILE}${CLR_RESET}"

  if [[ ! -f "${SCRIPT_DIR}/.venv/bin/python" ]]; then
    log_info "Creating .venv..."
    python3 -m venv "${SCRIPT_DIR}/.venv"
  fi
  "${SCRIPT_DIR}/.venv/bin/pip" install --quiet -r "${SCRIPT_DIR}/requirements.txt"
  exec "${SCRIPT_DIR}/.venv/bin/python" "${SCRIPT_DIR}/astrace.py" "${PASSTHROUGH_ARGS[@]}"
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
  FINAL_ARGS=()
  for arg in "${PASSTHROUGH_ARGS[@]}"; do
    [[ "$arg" == "$ABSOLUTE_PATH" || "$arg" == "$SOURCE_FILE_INPUT" ]] && arg="${CONTAINER_SRC_DIR}/${SOURCE_FILE}"
    FINAL_ARGS+=("$arg")
  done

  VOL_ARG=()
  [[ -n "$SOURCE_DIR" ]] && VOL_ARG=("--volume" "${SOURCE_DIR}:${CONTAINER_SRC_DIR}:ro")

  exec env COMPOSE_PROGRESS=quiet docker compose \
    run --rm "${VOL_ARG[@]}" audit python astrace.py "${FINAL_ARGS[@]}"
fi
