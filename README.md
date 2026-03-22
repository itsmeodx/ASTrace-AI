# LogicAudit 🔍

## AST-Aware C/C++ AI Security Auditor

LogicAudit uses `libclang` to parse your C/C++ source into an Abstract Syntax Tree, slices out only the functions containing high-risk operations, and sends them to an LLM that reasons through the exact execution path that causes each bug — returning a structured **Logic Trace** report directly in your terminal.

---

## Why LogicAudit?

Classic static analysers (Clang-Tidy, cppcheck) operate on surface-level patterns. LogicAudit operates on **program logic**:

| Capability                         | Pattern-Based Linters | LogicAudit |
| ---------------------------------- | --------------------- | ---------- |
| Buffer overflow (constant index)   | ✅                    | ✅         |
| Use-after-free across branches     | ❌                    | ✅         |
| Double-free in error paths         | ❌                    | ✅         |
| Memory leak on early return        | ❌                    | ✅         |
| Integer overflow → heap corruption | ❌                    | ✅         |

### How it works

```text
Source file
    │
    ▼
libclang AST Parser
    │   Walk AST, find functions containing:
    │   • malloc / calloc / realloc / free
    │   • Pointer arithmetic (BINARY_OPERATOR)
    │   • Array subscripts (ARRAY_SUBSCRIPT_EXPR)
    ▼
AST Slicer  ──→  Only ~10–30% of source sent to LLM (saves tokens)
    │
    ▼
LLM Provider  (OpenAI GPT-4o or Google Gemini 2.0)
    │   Returns: severity, vulnerability_type,
    │            logic_trace[] (step-by-step path to the bug),
    │            recommendation
    ▼
Rich Terminal Dashboard
```

---

## Quick Start (Docker — zero setup required)

### 1. Clone and configure

```bash
git clone https://github.com/yourorg/logicaudit.git
cd logicaudit
cp .env.example .env
# Open .env and choose your provider + set the appropriate API key
```

### 2. Audit a file

By default, the script builds and runs via Docker:
```bash
chmod +x audit.sh
./audit.sh path/to/your/file.c
```

If you prefer to run natively on your host machine without Docker:
```bash
./audit.sh --local path/to/your/file.c
```
*(Passing `--local` for the first time will automatically create a `.venv` and install all required dependencies for you!)*

The script will:

- Auto-build the Docker image on first run (cached on subsequent runs)
- Mount only the target file's directory into the container (read-only)
- Stream the Rich-formatted report to your terminal

### Example output

```text
╭─ LogicAudit — vulnerable.c ──────────────────────────────────────────────╮
│  Finding Summary                                                           │
│  🔴 CRITICAL  1                                                            │
│  🟠 HIGH      1                                                            │
╰─ 2 functions analysed ────────────────────────────────────────────────────╯

┌─ #1  Use-After-Free  in  process_request() ──────────────────────────────┐
│ 🔴 CRITICAL                                                                │
│ ┌──────┬──────────────────────────────────────────────────────────────┐   │
│ │ Step │ Logic Trace                                                   │   │
│ ├──────┼──────────────────────────────────────────────────────────────┤   │
│ │ 1    │ Buffer `buf` allocated with malloc(size) at line 12           │   │
│ │ 2    │ Error branch at line 18 calls free(buf) and returns           │   │
│ │ 3    │ Control continues in caller; buf is dereferenced at line 31   │   │
│ └──────┴──────────────────────────────────────────────────────────────┘   │
│ 💡 Recommendation: Set buf = NULL after free() and guard dereferences     │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## LLM Providers

Set `LLM_PROVIDER` in your `.env` to select your preferred provider.

### OpenAI (default)

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
# OPENAI_MODEL=gpt-4o   # optional, default: gpt-4o
```

### Google Gemini

```bash
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIza...
# GEMINI_MODEL=gemini-2.0-flash   # optional, default: gemini-2.0-flash
```

> Uses the new **`google-genai`** unified SDK (Gemini 2.0+). The legacy `google-generativeai` SDK reached EOL in November 2025.

---

## Local Development (without Docker)

You can run the engine directly using the `.venv` or by passing the `--local` flag to the runner script.

1. Ensure you have `clang` and `libclang` installed natively on your OS.
2. Set your API key in `.env` (copied from `.env.example`).
3. Run the audit:
   ```bash
   ./audit.sh --local path/to/file.c
   ```
   *The script will seamlessly generate its own `.venv` and install dependencies on its very first run!*

> **Tip:** If `libclang` is not found automatically, set `CLANG_LIBRARY_PATH` in your `.env` to the path of your `libclang.so` / `libclang.dylib`.

---

## Configuration

All options are set via `.env` (copied from `.env.example`):

| Variable             | Required  | Default            | Description                      |
| -------------------- | --------- | ------------------ | -------------------------------- |
| `LLM_PROVIDER`       | ❌        | `openai`           | Provider: `openai` or `gemini`   |
| `OPENAI_API_KEY`     | if openai | —                  | OpenAI API key                   |
| `OPENAI_MODEL`       | ❌        | `gpt-4o`           | OpenAI model                     |
| `GEMINI_API_KEY`     | if gemini | —                  | Google AI Studio API key         |
| `GEMINI_MODEL`       | ❌        | `gemini-2.0-flash` | Gemini model                     |
| `CLANG_LIBRARY_PATH` | ❌        | auto-detect        | Path to `libclang.so` / `.dylib` |

---

## Project Structure

```text
LogicAudit/
├── logicaudit.py      # Core engine: AST slicer + LLM providers + Rich UI
├── audit.sh           # Bash runner (Docker orchestration)
├── Dockerfile         # Multi-stage image (builder + slim runtime)
├── compose.yaml       # Docker Compose service definition
├── requirements.txt   # Pinned Python dependencies
├── .env.example       # API key template
├── .dockerignore      # Prevents .env and secrets from entering build context
└── README.md
```

---

## Security Notes

- `.env` is **never copied into the Docker image**. It is injected at runtime via `compose.yaml`'s `env_file` directive.
- The container runs as a **non-root user** (`appuser`).
- The container has a **read-only root filesystem** (`read_only: true` in `compose.yaml`).
- Source files are mounted **read-only** (`:ro` flag in `docker compose run`).

---

## Requirements

- Docker Engine ≥ 24 with Compose v2 (`docker compose`)
- An API key for your chosen provider (OpenAI or Google AI Studio)
