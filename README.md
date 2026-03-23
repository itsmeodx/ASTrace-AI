# ASTrace AI (Educational PoC)

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Status Proof of Concept](https://img.shields.io/badge/status-Proof_of_Concept-orange)

**ASTrace AI** is an educational proof-of-concept (PoC) demonstrating how to build highly cost-efficient, low-hallucination AI coding tools.

Instead of dumping vast amounts of source code into an expensive LLM context window, this project showcases a hybrid architecture: it uses a deterministic tool (`libclang`) to do the heavy lifting locally for free, cutting out 95% of the codebase, and only passing surgical, 30-line slices of high-risk memory logic to the LLM for deep analysis.

---

## Table of Contents

- [ASTrace AI (Educational PoC)](#astrace-ai-educational-poc)
  - [Table of Contents](#table-of-contents)
  - [The Problem: Token Bloat](#the-problem-token-bloat)
  - [The Solution: Hybrid AST Pre-filtering](#the-solution-hybrid-ast-pre-filtering)
  - [Demo](#demo)
  - [How it Works](#how-it-works)
  - [Built With](#built-with)
  - [Exploring the Code](#exploring-the-code)
  - [Getting Started](#getting-started)
    - [1. Configure Provider](#1-configure-provider)
    - [2. Run the Audit](#2-run-the-audit)
  - [Usage \& Options](#usage--options)
    - [Host Execution (No Docker)](#host-execution-no-docker)
    - [Example Output](#example-output)
  - [Key Educational Takeaways](#key-educational-takeaways)
  - [License](#license)

---

## The Problem: Token Bloat

Most AI-assisted security tools use a brute-force approach: they blindly dump your entire C file into the LLM context window.

This causes three massive problems:

1. **Skyrocketing API Costs**: You pay for every token of perfectly safe, irrelevant code.
2. **Context Window Limits**: Large legacy codebases simply don't fit.
3. **Hallucinations**: The model gets confused by thousands of lines of background noise, leading to false positives and generic advice.

## The Solution: Hybrid AST Pre-filtering

ASTrace AI demonstrates a smarter, heavily optimized pipeline

1. **Free Local Parsing**: `libclang` parses the Abstract Syntax Tree (AST) locally.
2. **Deterministic Slicing**: It extracts _only_ the specific functions that physically contain risky memory operations (`malloc`, `free`, pointer arithmetic, array subscripts).
3. **Surgical LLM Execution**: The LLM is forced to analyze only these isolated, highly volatile function slices.

Because the LLM only operates on tiny, highly curated slices of logic, API costs drop to **near-zero** (often less than $0.0001 per audit) and hallucination rates are **significantly reduced**, though manual verification remains essential.

---

## Demo

![ASTrace AI Demo](demo.gif)

---

## How it Works

```text
Source file
    │
    ▼
libclang AST Parser
    │   Walk AST locally (Cost: $0.00)
    │   Find functions containing `malloc` / `free` / pointer math
    ▼
AST Slicer
    │   Discard 95% of safe code
    ▼
LLM Provider  (OpenAI GPT-4o / Gemini 2.0)
    │   Analyze targeted 30-line slices
    │   Generate step-by-step Logic Traces
    ▼
Rich Terminal Dashboard
```

---

## Built With

- **Language**: Python 3.11+
- **AST Parsing**: `libclang` (C/C++ LLVM bindings)
- **LLM Integrations**: `openai` and `google-genai` SDKs
- **Terminal Dashboard**: `rich`
- **Containerization**: Docker Compose

---

## Exploring the Code

This project is built for educational review. If you're interested in how the AST slicing or Docker orchestration works, check out the core files:

```text
ASTrace-AI/
├── astrace.py         # The core PoC: Traverses AST with libclang, slices code, queries LLM
├── astrace.sh         # Bash runner demonstrating secure, read-only Docker orchestration
├── Dockerfile         # Multi-stage image building the libclang bindings
├── compose.yaml       # Docker Compose service defining the secure runtime
├── requirements.txt   # Pinned Python dependencies
└── tests/             # Sample vulnerable C files used to test the LLM's reasoning
```

---

## Getting Started

### 1. Configure Provider

Clone the repository and set up your environment variables:

```bash
git clone https://github.com/itsmeodx/ASTrace-AI.git
cd ASTrace-AI
cp .env.example .env
# Open .env and add your OpenAI or Gemini AI Studio key
```

### 2. Run the Audit

The core runner script demonstrates secure Docker containerization, mounting files as strictly read-only:

```bash
chmod +x astrace.sh
./astrace.sh tests/test_leak.c
```

---

## Usage & Options

The `astrace.sh` runner supports several flags for host-based execution and environment diagnostics:

```bash
Usage: astrace.sh [options] <path/to/file.c>
```

| Flag        | Shorthand | Description                                                        |
| :---------- | :-------- | :----------------------------------------------------------------- |
| `--local`   | `-l`      | Run directly on the host using a Python `.venv` (bypasses Docker). |
| `--check`   | `-c`      | Run environment diagnostics (libclang, API keys, dependencies).    |
| `--version` | `-v`      | Show the current version of ASTrace AI.                            |
| `--`        |           | POSIX separator to protect following arguments from shell parsing. |

### Host Execution (No Docker)

If you prefer not to use Docker, the script automatically provisions a virtual environment for you:

```bash
./astrace.sh -l tests/test_leak.c
```

### Example Output

Notice how the tool explicitly lists only the exact lines of execution that cause the bug, based only on the tiny slice it was given.

```text
╭─ ASTrace AI — test_leak.c ──────────────────────────────────────────────╮
│  Finding Summary                                                           │
│  🔴 CRITICAL  1                                                            │
╰─ 2 functions analysed ────────────────────────────────────────────────────╯

┌─ #1  Memory Leak  in  parse_records() ──────────────────────────────┐
│ 🔴 CRITICAL                                                                │
│ ┌──────┬──────────────────────────────────────────────────────────────┐   │
│ │ Step │ Logic Trace                                                   │   │
│ ├──────┼──────────────────────────────────────────────────────────────┤   │
│ │ 1    │ `records` array allocated with malloc() at line 28            │   │
│ │ 2    │ Error condition triggered at line 34 (fopen fails)            │   │
│ │ 3    │ Function returns at line 36 without freeing `records`         │   │
│ └──────┴──────────────────────────────────────────────────────────────┘   │
│ 💡 Recommendation: Add a `goto cleanup` label to ensure `free(records)` │
└────────────────────────────────────────────────────────────────────────────┘
```

> **Note**: This is an educational codebase demonstrating AI-agent optimization concepts. It is not intended for auditing production environments or systems.

---

## Key Educational Takeaways

If you are studying or forking this repository to build your own AI coding agents, look for these implemented patterns:

- **Physical Context Constraint**: The LLM's focus isn't constrained by a weak `System Prompt` telling it to ignore safe code; it's constrained physically because the AST Slicer literally removes the safe code before the prompt is built.
- **Fail-Fast Local Pipelines**: Using expensive LLMs to "search" or "grep" code is an anti-pattern. Use deterministic, $0 cost tooling (`libclang`, `tree-sitter`) to find the exact target (the needle), and only invoke the LLM to reason about the logic (the thread).
- **Secure Architecture by Default**: The Docker runner demonstrates how to execute untrusted code or heavily parameterized audits inside a hardened, read-only filesystem container.

---

## License

Distributed under the GNU GPL v3 License. See [LICENSE](LICENSE) for more information.

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/itsmeodx"><b>itsmeodx</b></a> for the security community. <br/>
  <b>ASTrace AI</b> • Optimized AI-Agent Architectures
</p>

<p align="center">
  <a href="https://github.com/itsmeodx/ASTrace-AI/stargazers">
    <img src="https://img.shields.io/github/stars/itsmeodx/ASTrace-AI?style=social" alt="GitHub stars">
  </a>
  &nbsp;&nbsp;
  <a href="https://github.com/itsmeodx/ASTrace-AI/issues">
    <img src="https://img.shields.io/github/issues/itsmeodx/ASTrace-AI" alt="GitHub issues">
  </a>
</p>
