#!/usr/bin/env python3
"""
# ─── ASTrace AI – AST-Aware C/C++ Security Auditor ─────────────────────────────
==============================================
Slices a C/C++ source file down to only the functions that contain high-risk
memory or pointer operations, then asks an LLM to perform a deep logic-trace
analysis and return structured findings.

Pipeline:
  1. libclang  → parse source, extract function AST nodes
  2. Slicer    → keep only functions with risky ops (malloc, free, ptr arith…)
  3. LLM       → analyse slices, return JSON matching AuditReport schema
  4. Rich UI   → render findings as styled terminal panels
"""

from __future__ import annotations

import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Iterator, Protocol

# Third-party deps – type: ignore comments silence IDEs that aren't venv-aware.
from dotenv import load_dotenv
from pydantic import BaseModel
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Load API keys from a local .env, overriding any stale shell variables.
load_dotenv(Path(__file__).parent / ".env", override=True)

# Shared Rich console instance used throughout the module.
console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# §1  libclang Discovery
# ─────────────────────────────────────────────────────────────────────────────

# Well-known libclang locations across Linux, macOS, and Windows.
# The user can skip this list entirely by setting CLANG_LIBRARY_PATH.
_LIBCLANG_SEARCH_PATHS: list[str] = [
    # Linux (apt / dpkg)
    "/usr/lib/llvm-14/lib/libclang.so",
    "/usr/lib/llvm-14/lib/libclang.so.1",
    "/usr/lib/llvm-15/lib/libclang.so",
    "/usr/lib/llvm-16/lib/libclang.so",
    "/usr/lib/llvm-17/lib/libclang.so",
    "/usr/lib/libclang.so",
    "/usr/lib/libclang.so.1",
    "/usr/lib/x86_64-linux-gnu/libclang.so.1",
    "/usr/lib/x86_64-linux-gnu/libclang-14.so.1",
    # macOS (Homebrew & Xcode CLT)
    "/usr/local/opt/llvm/lib/libclang.dylib",
    "/opt/homebrew/opt/llvm/lib/libclang.dylib",
    "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib",
    # Windows (standard LLVM installer)
    r"C:\Program Files\LLVM\bin\libclang.dll",
    r"C:\Program Files (x86)\LLVM\bin\libclang.dll",
]


def find_libclang() -> str | None:
    """
    Locate the libclang shared library on the host system.

    Checks the ``CLANG_LIBRARY_PATH`` environment variable first so users
    can always override auto-detection on non-standard setups. Falls back
    to probing the well-known paths in ``_LIBCLANG_SEARCH_PATHS``.

    Returns:
        Absolute path to the library file, or ``None`` if it cannot be found.
    """
    env_path = os.environ.get("CLANG_LIBRARY_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    for candidate in _LIBCLANG_SEARCH_PATHS:
        if Path(candidate).exists():
            return candidate

    return None


# Clang resource directories contain compiler built-in headers (stdint.h, etc.).
# Without one of these, libclang can't resolve types from <stddef.h> or <stdarg.h>.
_RESOURCE_DIR_CANDIDATES: list[str] = [
    "/usr/lib/llvm-14/lib/clang/14.0.6",
    "/usr/lib/llvm-15/lib/clang/15.0.7",
    "/usr/lib/llvm-16/lib/clang/16.0.6",
    "/usr/lib/llvm-17/lib/clang/17.0.6",
    "/usr/lib/llvm-18/lib/clang/18",
    "/usr/local/opt/llvm/lib/clang/14",
    "/usr/local/opt/llvm/lib/clang/15",
]


def _build_clang_args() -> list[str]:
    """
    Build the compiler argument list passed to ``cindex.Index.parse()``.

    Without ``-resource-dir`` and ``-isystem`` flags, libclang silently
    fails to resolve ``malloc``/``free`` as ``CALL_EXPR`` nodes — the slicer
    would return zero results even on clearly dangerous code.

    Returns:
        List of compiler flag strings ready to pass to ``cindex.Index.parse``.
    """
    args: list[str] = ["-std=c11"]

    resource_dir = os.environ.get("CLANG_RESOURCE_DIR")
    if not resource_dir:
        for candidate in _RESOURCE_DIR_CANDIDATES:
            if Path(candidate).is_dir():
                resource_dir = candidate
                break

    if resource_dir:
        args.extend(["-resource-dir", str(resource_dir)])

    for inc in ("/usr/include", "/usr/include/x86_64-linux-gnu", "/usr/local/include"):
        if Path(inc).is_dir():
            args.extend(["-isystem", inc])

    return args


# ─────────────────────────────────────────────────────────────────────────────
# §2  AST Slicer
# ─────────────────────────────────────────────────────────────────────────────

# Functions that directly manage heap memory. Any call to one of these
# inside a function body flags it for LLM analysis.
_RISKY_CALLS: frozenset[str] = frozenset(
    {"malloc", "calloc", "realloc", "free", "alloca", "mmap", "munmap"}
)


def _slurp(path: str) -> list[str]:
    """
    Read a file into a list of raw line strings.

    Loading the entire file upfront lets us extract any function range with
    a cheap list slice instead of re-opening the file for each snippet.

    Args:
        path: Absolute or relative path to the source file.

    Returns:
        List of lines including their newline characters, suitable for
        passing to ``_extract_lines``.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def _extract_lines(source_lines: list[str], start_line: int, end_line: int) -> str:
    """
    Extract a contiguous range of lines from a pre-loaded line list.

    Args:
        source_lines: Full file contents as returned by ``_slurp``.
        start_line:   1-indexed first line to include (libclang convention).
        end_line:     1-indexed last line to include (inclusive).

    Returns:
        A single string concatenating all lines in ``[start_line, end_line]``.
    """
    return "".join(source_lines[start_line - 1 : end_line])  # type: ignore[index]


def _is_risky_cursor(cursor: "clang.cindex.Cursor") -> bool:  # type: ignore[name-defined] # noqa: F821
    """
    Determine whether an AST node represents a dangerous memory operation.

    Flags explicit calls to known risky functions (``malloc``, ``free``, etc.),
    raw pointer arithmetic via binary operators, and direct array subscript
    expressions.

    Args:
        cursor: A libclang AST cursor to evaluate.

    Returns:
        ``True`` if the node should mark its enclosing function for LLM review.
    """
    import clang.cindex as cindex  # type: ignore[import-not-found]

    kind = cursor.kind
    if kind == cindex.CursorKind.CALL_EXPR and cursor.spelling in _RISKY_CALLS:
        return True
    if kind in (cindex.CursorKind.BINARY_OPERATOR, cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR):
        return True
    return False


def _walk(cursor: "clang.cindex.Cursor") -> Iterator["clang.cindex.Cursor"]:  # type: ignore[name-defined] # noqa: F821
    """
    Yield every AST node in a subtree via depth-first, pre-order traversal.

    Args:
        cursor: Root cursor to start the walk from.

    Yields:
        Each ``clang.cindex.Cursor`` in the subtree, starting with ``cursor``
        itself before descending into its children.
    """
    yield cursor
    for child in cursor.get_children():
        yield from _walk(child)


def slice_risky_functions(source_file: str) -> list[dict]:
    """
    Parse a C/C++ source file and extract functions that contain risky operations.

    This is the core analysis step. It builds a full AST via libclang, walks
    only the top-level function definitions from the file itself (ignoring
    ``#include``'d headers), and returns a curated list of snippets for the LLM.

    Args:
        source_file: Path to the ``.c`` or ``.cpp`` file to analyse.

    Returns:
        List of descriptor dicts, each with the following keys:

        - ``name``       — function spelling (e.g. ``"handle_error"``)
        - ``start_line`` — 1-indexed first line of the function body
        - ``end_line``   — 1-indexed last line of the function body
        - ``source``     — raw source text for that range
        - ``risk_ops``   — sorted list of flagged operations (e.g. ``"call:free"``)

    Raises:
        SystemExit: If libclang cannot be located, loaded, or if the file
                    cannot be parsed as valid C/C++.
    """
    import clang.cindex as cindex  # type: ignore[import-not-found]

    libclang_path = find_libclang()
    if libclang_path is None:
        console.print(
            "[bold red]ERROR:[/] Could not locate libclang. "
            "Set CLANG_LIBRARY_PATH or install the clang package."
        )
        sys.exit(1)

    try:
        cindex.Config.set_library_file(libclang_path)
    except cindex.LibclangError as exc:
        console.print(f"[bold red]ERROR:[/] Failed to load libclang – {exc}")
        sys.exit(1)

    index = cindex.Index.create()
    try:
        tu = index.parse(source_file, args=_build_clang_args())
    except cindex.TranslationUnitLoadError:
        console.print(
            f"[bold red]ERROR:[/] Failed to parse [italic]{source_file}[/]. "
            "Ensure it is a valid C/C++ source file."
        )
        sys.exit(1)

    # Severity >= 3 means Error or Fatal. We still proceed — a missing system
    # header won't stop us from finding structural vulnerabilities.
    errors = [d for d in tu.diagnostics if d.severity >= 3]
    if errors:
        console.print("[bold yellow]⚠  Parser diagnostics (proceeding anyway):[/]")
        for diag in errors[:10]:  # type: ignore[index]
            console.print(f"   [yellow]{diag.spelling}[/]")

    source_lines = _slurp(source_file)

    # All cursor kinds that represent a callable definition.
    fn_kinds = (
        cindex.CursorKind.FUNCTION_DECL,
        cindex.CursorKind.CXX_METHOD,
        cindex.CursorKind.CONSTRUCTOR,
        cindex.CursorKind.DESTRUCTOR,
    )

    result: list[dict] = []

    # Walk only the TU's direct children so we never descend into #include'd headers.
    # Using cursor.semantic_parent to walk upward is unreliable in plain C — it
    # returns the TU root for most expressions, not the enclosing function.
    for top in tu.cursor.get_children():
        if top.location.file is None or top.location.file.name != source_file:
            continue
        if top.kind not in fn_kinds or not top.is_definition():
            continue

        risk_ops: set[str] = set()
        for child in _walk(top):
            if not _is_risky_cursor(child):
                continue
            if child.kind == cindex.CursorKind.CALL_EXPR:
                risk_ops.add(f"call:{child.spelling}")
            elif child.kind == cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                risk_ops.add("array_subscript")
            else:
                risk_ops.add("pointer_arithmetic")

        if not risk_ops:
            continue

        start, end = top.extent.start.line, top.extent.end.line
        result.append({
            "name":       top.spelling,
            "start_line": start,
            "end_line":   end,
            "source":     _extract_lines(source_lines, start, end),
            "risk_ops":   sorted(risk_ops),
        })

    return result


# ─────────────────────────────────────────────────────────────────────────────
# §3  Pydantic Schemas  (LLM structured output contract)
# ─────────────────────────────────────────────────────────────────────────────
# Passing these classes directly to the LLM APIs (OpenAI response_format /
# Gemini response_schema) forces the model into a strict JSON shape, removing
# any need for fragile regex post-processing.


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"


class Finding(BaseModel):
    """A single confirmed vulnerability with a numbered execution-path trace."""

    severity:           Severity
    vulnerability_type: str
    function_name:      str
    # Step-by-step chain of reasoning that shows exactly how the bug fires.
    logic_trace:        list[str]
    recommendation:     str


class AuditReport(BaseModel):
    """Top-level envelope returned by the LLM for one source file."""

    file_analysed:   str
    findings:        list[Finding]
    overall_summary: str


# ─────────────────────────────────────────────────────────────────────────────
# §4  LLM Integration
# ─────────────────────────────────────────────────────────────────────────────

# System prompt doubles as the auditor's persona and output contract.
# Keeping it tight reduces hallucination and ensures logic_trace is always present.
_SYSTEM_PROMPT = """\
You are an expert C/C++ memory-safety and security auditor.
You will receive one or more function snippets extracted from a C/C++ source file.
Your job is to identify real security vulnerabilities: use-after-free, double-free,
memory leaks, buffer overflows, integer overflows leading to heap corruption, and
similar logic-level bugs that classic linters miss.

IMPORTANT RULES
───────────────
• Only report genuine issues, not style problems.
• For every finding, populate `logic_trace` with a numbered array of strings
  that walk through the exact execution path that causes the bug
  (e.g. "1. Buffer allocated with size N at line 10",
        "2. User-controlled index is NOT bounds-checked",
        "3. Write at buf[index] overwrites heap metadata at line 18").
• If the code is clean, return an empty `findings` list and say so in `overall_summary`.
• Always set `file_analysed` to the filename you were given.
"""


def _build_user_message(source_file: str, fn_slices: list[dict]) -> str:
    """
    Serialize the slicer output into a fenced-code markdown prompt.

    Each function slice is rendered as a titled markdown section with its
    detected risk operations listed above the raw C/C++ source block.

    Args:
        source_file: Original file path, shown to the LLM for context.
        fn_slices:   List of function descriptor dicts from ``slice_risky_functions``.

    Returns:
        A single markdown string ready to use as the LLM user message.
    """
    blocks = []
    for fn in fn_slices:
        blocks.append(
            f"### Function `{fn['name']}` "
            f"(lines {fn['start_line']}–{fn['end_line']})\n"
            f"Risky ops detected: {', '.join(fn['risk_ops'])}\n\n"
            f"```c\n{fn['source']}```"
        )
    return f"File: `{source_file}`\n\n" + "\n\n---\n\n".join(blocks)


# Any callable matching this signature can be registered as a provider.
class _ProviderFn(Protocol):
    def __call__(self, source_file: str, fn_slices: list[dict]) -> AuditReport: ...


def _run_audit_openai(source_file: str, fn_slices: list[dict]) -> AuditReport:
    """
    Run the audit against the OpenAI API.

    Uses ``client.beta.chat.completions.parse()`` with ``response_format=AuditReport``
    to guarantee native Pydantic structured output — no regex post-processing needed.

    Args:
        source_file: Path to the source file being audited (included in the prompt).
        fn_slices:   Filtered function descriptors from ``slice_risky_functions``.

    Returns:
        A validated ``AuditReport`` instance.

    Raises:
        SystemExit: On import failure, missing API key, or a failed API call.
    """
    try:
        from openai import OpenAI  # type: ignore[import-not-found]
    except ImportError:
        console.print("[bold red]ERROR:[/] `openai` package is not installed.")
        sys.exit(1)

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        console.print(
            "[bold red]ERROR:[/] OPENAI_API_KEY is not set. "
            "Copy .env.example to .env and fill in your key."
        )
        sys.exit(1)

    model  = os.environ.get("OPENAI_MODEL", "gpt-4o")
    client = OpenAI(api_key=api_key)

    try:
        response = client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": _build_user_message(source_file, fn_slices)},
            ],
            response_format=AuditReport,
            temperature=0.1,
            max_tokens=4096,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]ERROR:[/] OpenAI request failed – {exc}")
        sys.exit(1)

    report = response.choices[0].message.parsed
    if report is None:
        console.print(f"[bold red]ERROR:[/] Model refused – {response.choices[0].message.refusal}")
        sys.exit(1)

    return report


def _run_audit_gemini(source_file: str, fn_slices: list[dict]) -> AuditReport:
    """
    Run the audit against the Google Gemini API.

    Requires the new ``google-genai`` unified SDK — **not** the deprecated
    ``google-generativeai`` package, which does not support Gemini 2.0+
    structured JSON output via ``response_schema``.

    Args:
        source_file: Path to the source file being audited (included in the prompt).
        fn_slices:   Filtered function descriptors from ``slice_risky_functions``.

    Returns:
        A validated ``AuditReport`` instance deserialized from the JSON response.

    Raises:
        SystemExit: On import failure, missing API key, API error, or a
                    malformed response that fails Pydantic validation.
    """
    try:
        from google import genai                      # type: ignore[import-not-found]
        from google.genai import types as genai_types # type: ignore[import-not-found]
    except ImportError:
        console.print(
            "[bold red]ERROR:[/] `google-genai` package is not installed. "
            "Run: pip install google-genai"
        )
        sys.exit(1)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        console.print(
            "[bold red]ERROR:[/] GEMINI_API_KEY is not set. "
            "Copy .env.example to .env and fill in your key."
        )
        sys.exit(1)

    model_name = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
    client     = genai.Client(api_key=api_key)
    config     = genai_types.GenerateContentConfig(
        temperature=0.1,
        response_mime_type="application/json",
        response_schema=AuditReport,
        system_instruction=_SYSTEM_PROMPT,
    )

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=_build_user_message(source_file, fn_slices),
            config=config,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]ERROR:[/] Gemini request failed – {exc}")
        sys.exit(1)

    # Gemini returns raw JSON in response.text; validate it through Pydantic.
    try:
        return AuditReport(**json.loads(response.text))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]ERROR:[/] Failed to parse Gemini response – {exc}")
        console.print(f"[dim]Raw: {response.text[:500]}[/]")
        sys.exit(1)


# Provider registry — add new backends here by mapping a key to a _ProviderFn.
# The key must match what the user sets in LLM_PROVIDER inside .env.
_PROVIDERS: dict[str, _ProviderFn] = {
    "openai": _run_audit_openai,
    "gemini": _run_audit_gemini,
}


def run_audit(source_file: str, fn_slices: list[dict]) -> AuditReport:
    """
    Dispatch the analysis to the configured LLM backend.

    Reads the ``LLM_PROVIDER`` environment variable (case-insensitive) and
    routes the call to the matching entry in ``_PROVIDERS``.

    Args:
        source_file: Path to the source file, forwarded to the provider.
        fn_slices:   Filtered function descriptors from ``slice_risky_functions``.

    Returns:
        A validated ``AuditReport`` from whichever backend was invoked.

    Raises:
        SystemExit: If ``LLM_PROVIDER`` is set to an unrecognized value.
    """
    provider = os.environ.get("LLM_PROVIDER", "openai").lower().strip()

    if provider not in _PROVIDERS:
        console.print(
            f"[bold red]ERROR:[/] Unknown LLM_PROVIDER '{provider}'. "
            f"Supported: {', '.join(repr(p) for p in _PROVIDERS)}"
        )
        sys.exit(1)

    return _PROVIDERS[provider](source_file, fn_slices)


# ─────────────────────────────────────────────────────────────────────────────
# §5  Rich Terminal UI
# ─────────────────────────────────────────────────────────────────────────────

# (Rich style string, display label) keyed by severity.
# Centralised here so colors and icons are consistent across every panel.
_SEVERITY_STYLES: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("bold white on red", "🔴 CRITICAL"),
    Severity.HIGH:     ("bold red",           "🟠 HIGH"),
    Severity.MEDIUM:   ("bold yellow",         "🟡 MEDIUM"),
    Severity.LOW:      ("bold blue",            "🔵 LOW"),
    Severity.INFO:     ("bold dim",             "⚪ INFO"),
}


def _severity_text(sev: Severity) -> Text:
    """
    Build a styled Rich ``Text`` label for the given severity level.

    Args:
        sev: The ``Severity`` enum value to render.

    Returns:
        A ``rich.text.Text`` instance styled with the appropriate color and emoji.
    """
    style, label = _SEVERITY_STYLES[sev]
    return Text(label, style=style)


def _build_finding_renderable(finding: Finding):  # noqa: ANN201
    """
    Assemble the Rich panel body for a single finding.

    Stacks three elements vertically: a severity badge, a numbered logic
    trace table, and a highlighted recommendation. Returns a ``Group`` so
    it can be embedded directly inside a ``rich.panel.Panel``.

    Args:
        finding: The ``Finding`` instance to render.

    Returns:
        A ``rich.console.Group`` containing the badge, trace table, and
        recommendation text, ready to pass to ``Panel``.
    """
    # Deferred import — avoids a circular reference with the top-level Console init.
    from rich.console import Group  # type: ignore[import-not-found]

    trace_table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        expand=True,
        padding=(0, 1),
    )
    trace_table.add_column("Step", style="bold cyan", width=5, no_wrap=True)
    trace_table.add_column("Logic Trace", style="white")

    for step in finding.logic_trace:
        # LLMs sometimes prefix steps with "1. ", "2. " etc. — keep them in their own column.
        parts = step.split(". ", 1)
        if len(parts) == 2 and parts[0].isdigit():
            trace_table.add_row(parts[0], parts[1])
        else:
            trace_table.add_row("→", step)

    rec_text = Text()
    rec_text.append("💡  Recommendation: ", style="bold green")
    rec_text.append(finding.recommendation, style="green")

    return Group(_severity_text(finding.severity), Text(""), trace_table, Text(""), rec_text)


def render_report(report: AuditReport) -> None:
    """
    Render a completed ``AuditReport`` to the terminal using Rich.

    Prints a header rule, then either a clean "no findings" panel or an
    overview banner followed by individual styled panels per finding.

    Args:
        report: The ``AuditReport`` returned by ``run_audit``.
    """
    console.print()
    console.print(Rule(f"[bold cyan]ASTrace AI[/] — [italic]{report.file_analysed}[/]", style="cyan"))

    # Early exit with a clean result if the LLM found no issues.
    if not report.findings:
        console.print(Panel(
            f"[bold green]✔  No findings.[/]\n\n{report.overall_summary}",
            title="[bold green]Audit Result[/]",
            border_style="green",
        ))
        return

    # ── Summary banner ──
    # Aggregate all findings by severity for a quick top-level overview.
    sev_counts: dict[str, int] = {}
    for f in report.findings:
        label = _SEVERITY_STYLES[f.severity][1]    # e.g. "🟠 HIGH"
        sev_counts[label] = sev_counts.get(label, 0) + 1

    # A compact two-column table: severity icon | count.
    summary_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary_table.add_column(style="bold")
    summary_table.add_column()
    for label, count in sev_counts.items():
        summary_table.add_row(label, str(count))

    # Truncate the overall summary to keep the subtitle to one neat line.
    console.print(Panel(
        summary_table,
        title="[bold]Finding Summary[/]",
        subtitle=str(report.overall_summary)[:120],  # type: ignore[index]
        border_style="cyan",
    ))

    # ── Individual finding panels ──
    for idx, finding in enumerate(report.findings, start=1):
        # Compose the panel title from multiple styled text segments.
        header = Text()
        header.append(f"#{idx}  ", style="bold dim")
        header.append(f"{_severity_text(finding.severity)}  ")
        header.append(finding.vulnerability_type, style="bold")
        header.append(f"  in  {finding.function_name}()", style="italic dim")

        console.print()
        console.print(Panel(
            _build_finding_renderable(finding),
            title=str(header),
            # Pull the first word from the severity style (e.g. "bold red" → "bold") for border color.
            border_style=_SEVERITY_STYLES[finding.severity][0].split(" ")[0],
        ))

    console.print()
    console.print(Rule(style="dim"))
    console.print(f"[dim]Audit complete – {len(report.findings)} finding(s) reported.[/]\n")


# ─────────────────────────────────────────────────────────────────────────────
# §6  Entry Point
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    """
    Entry point for the three-stage audit pipeline.

    Expects a single positional argument (the path to a C/C++ source file)
    and orchestrates the full flow: AST parsing → LLM analysis → terminal render.

    Raises:
        SystemExit: If no argument is provided, the file does not exist, or
                    any downstream step fails (libclang, API call, etc.).
    """
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/]  astrace.py <path/to/file.c>")
        sys.exit(1)

    # The only accepted argument is the path to the C/C++ source file.
    source_path = sys.argv[1]

    if not Path(source_path).is_file():
        console.print(f"[bold red]ERROR:[/] File not found: [italic]{source_path}[/]")
        sys.exit(1)

    # ── Stage 1: Parse & slice ──
    with console.status("[bold cyan]Parsing AST and slicing risky functions…[/]", spinner="dots"):
        fn_slices = slice_risky_functions(source_path)

    # If the slicer finds nothing, the file has no memory-management code to audit.
    # No need to spend LLM tokens on it.
    if not fn_slices:
        console.print(Panel(
            "[bold green]✔  No high-risk code patterns found.[/]\n"
            "The file does not appear to contain memory management, "
            "pointer arithmetic, or array subscript operations.",
            title="[bold green]Audit Result[/]",
            border_style="green",
        ))
        return

    # Print a short manifest of what was discovered before sending to the LLM.
    console.print(f"[cyan]AST slicer found [bold]{len(fn_slices)}[/] function(s) containing high-risk operations.[/]")
    for fn in fn_slices:
        console.print(
            f"  [dim]→[/] [bold]{fn['name']}[/]()  "
            f"[dim](lines {fn['start_line']}–{fn['end_line']}, ops: {', '.join(fn['risk_ops'])})[/]"
        )

    # ── Stage 2: LLM analysis ──
    with console.status("[bold cyan]Analysing with LLM (Logic Trace mode)…[/]", spinner="dots"):
        report = run_audit(source_path, fn_slices)

    # ── Stage 3: Render ──
    render_report(report)


if __name__ == "__main__":
    main()
