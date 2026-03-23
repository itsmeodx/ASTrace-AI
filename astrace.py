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

import importlib
import json
import os
import subprocess
import sys
from argparse import ArgumentParser
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Protocol

# Third-party deps – type: ignore comments silence IDEs that aren't venv-aware.
from dotenv import load_dotenv
from pydantic import BaseModel
from rich import box
from rich.console import Console, Group
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
    """Locate the libclang shared library on the host system using a cascading search."""
    # 1. Env Var Check
    env_path = os.environ.get("CLANG_LIBRARY_PATH")
    if env_path and Path(env_path).exists():
        return str(Path(env_path).absolute())

    def _query(cmd: list[str], flag: str = "") -> str | None:
        try:
            out = (
                subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            )
            return out if out and (not flag or flag in out) else None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    # 2. Query llvm-config or clang
    libdir = _query(["llvm-config", "--libdir"])
    if libdir:
        for ext in (".so", ".so.1", ".dylib", ".dll"):
            path = Path(libdir) / f"libclang{ext}"
            if path.exists():
                return str(path.absolute())

    clang_lib = _query(["clang", "-print-file-name=libclang.so"], "libclang")
    if clang_lib and Path(clang_lib).is_absolute() and Path(clang_lib).exists():
        return clang_lib

    # 3. Probabilistic search
    for candidate in _LIBCLANG_SEARCH_PATHS:
        if Path(candidate).exists():
            return str(Path(candidate).absolute())
    return None


def _init_clang() -> Any:
    """Initialize clang.cindex and return the module, or exit on failure."""
    lib_path = find_libclang()
    if not lib_path:
        console.print(
            "[bold red]ERROR:[/] Could not locate libclang. Set `CLANG_LIBRARY_PATH`."
        )
        sys.exit(1)

    try:
        import clang.cindex as cindex  # type: ignore[import-not-found]

        cindex.Config.set_library_file(lib_path)
        return cindex
    except (ImportError, cindex.LibclangError) as exc:
        console.print(f"[bold red]ERROR:[/] Failed to load libclang – {exc}")
        sys.exit(1)


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


def _is_risky_cursor(cursor: Any, cindex: Any) -> bool:
    """Determine whether an AST node represents a dangerous memory operation."""
    if cursor.kind == cindex.CursorKind.CALL_EXPR and cursor.spelling in _RISKY_CALLS:
        return True
    return cursor.kind in (
        cindex.CursorKind.BINARY_OPERATOR,
        cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR,
    )


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
        A tuple of (type_definitions: list[str], function_slices: list[dict]).
    """
    cindex = _init_clang()
    index = cindex.Index.create()
    try:
        tu = index.parse(source_file, args=_build_clang_args())
    except cindex.TranslationUnitLoadError:
        console.print(f"[bold red]ERROR:[/] Failed to parse [italic]{source_file}[/].")
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
    func_kinds = (
        cindex.CursorKind.FUNCTION_DECL,
        cindex.CursorKind.CXX_METHOD,
        cindex.CursorKind.CONSTRUCTOR,
        cindex.CursorKind.DESTRUCTOR,
    )
    # Global definitions to extract for context.
    type_kinds = (
        cindex.CursorKind.STRUCT_DECL,
        cindex.CursorKind.UNION_DECL,
        cindex.CursorKind.ENUM_DECL,
        cindex.CursorKind.TYPEDEF_DECL,
    )

    type_defs: list[str] = []
    fn_slices: list[dict] = []

    # Walk only the TU's direct children so we never descend into #include'd headers.
    # Using cursor.semantic_parent to walk upward is unreliable in plain C — it
    # returns the TU root for most expressions, not the enclosing function.
    for top in tu.cursor.get_children():
        if top.location.file is None or top.location.file.name != source_file:
            continue

        if top.kind in type_kinds:
            start, end = top.extent.start.line, top.extent.end.line
            type_defs.append(_extract_lines(source_lines, start, end))
            continue

        if top.kind not in func_kinds or not top.is_definition():
            continue

        risk_ops: set[str] = set()
        for child in _walk(top):
            if not _is_risky_cursor(child, cindex):
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
        fn_slices.append(
            {
                "name": top.spelling,
                "start_line": start,
                "end_line": end,
                "source": _extract_lines(source_lines, start, end),
                "risk_ops": sorted(risk_ops),
            }
        )

    return type_defs, fn_slices


# ─────────────────────────────────────────────────────────────────────────────
# §3  Pydantic Schemas  (LLM structured output contract)
# ─────────────────────────────────────────────────────────────────────────────
# Passing these classes directly to the LLM APIs (OpenAI response_format /
# Gemini response_schema) forces the model into a strict JSON shape, removing
# any need for fragile regex post-processing.


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Finding(BaseModel):
    """A single confirmed vulnerability with a numbered execution-path trace."""

    severity: Severity
    vulnerability_type: str
    function_name: str
    # Step-by-step chain of reasoning that shows exactly how the bug fires.
    logic_trace: list[str]
    recommendation: str


class AuditReport(BaseModel):
    """Top-level envelope returned by the LLM for one source file."""

    file_analysed: str
    findings: list[Finding]
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

CONTEXTUAL TYPE DEFINITIONS
───────────────────────────
If the user provides a "Global Type Definitions" section, use it to resolve
member types, struct layouts, and buffer sizes. For example, if a struct member
is defined as `char name[64]`, it is a fixed-size buffer inside the struct,
NOT an uninitialized pointer.
"""


def _build_user_message(
    source_file: str, type_defs: list[str], fn_slices: list[dict]
) -> str:
    """
    Serialize the slicer output into a fenced-code markdown prompt.

    Each function slice is rendered as a titled markdown section with its
    detected risk operations listed above the raw C/C++ source block.

    Args:
        source_file: Original file path, shown to the LLM for context.
        type_defs:   List of raw C/C++ type definition snippets.
        fn_slices:   List of function descriptor dicts from ``slice_risky_functions``.

    Returns:
        A single markdown string ready to use as the LLM user message.
    """
    sections = []

    # 1. Global Context (Types)
    if type_defs:
        sections.append(
            "## Global Type Definitions\n"
            + "\n\n".join(f"```c\n{td}```" for td in type_defs)
        )

    # 2. Function Slices
    sections.append("## Function Snippets for Audit")
    for fn in fn_slices:
        sections.append(
            f"### Function `{fn['name']}` "
            f"(lines {fn['start_line']}–{fn['end_line']})\n"
            f"Risky ops detected: {', '.join(fn['risk_ops'])}\n\n"
            f"```c\n{fn['source']}```"
        )

    return f"File: `{source_file}`\n\n" + "\n\n---\n\n".join(sections)


# Any callable matching this signature can be registered as a provider.
class _ProviderFn(Protocol):
    def __call__(
        self, source_file: str, type_defs: list[str], fn_slices: list[dict]
    ) -> AuditReport: ...


def _get_api_config(provider: str) -> tuple[str, str, str]:
    """Helper to load and validate LLM provider config."""
    key_name = "OPENAI_API_KEY" if provider == "openai" else "GEMINI_API_KEY"
    key = os.environ.get(key_name)
    if not key:
        console.print(f"[bold red]ERROR:[/] {key_name} is not set.")
        sys.exit(1)

    model_env = "OPENAI_MODEL" if provider == "openai" else "GEMINI_MODEL"
    default_model = "gpt-4o" if provider == "openai" else "gemini-2.0-flash"
    return key, os.environ.get(model_env, default_model), provider


def _run_audit_openai(
    source_file: str, type_defs: list[str], fn_slices: list[dict]
) -> AuditReport:
    """Run the audit against OpenAI using native completion parsing."""
    try:
        from openai import OpenAI
    except ImportError:
        console.print("[bold red]ERROR:[/] `openai` package is not installed.")
        sys.exit(1)

    key, model, _ = _get_api_config("openai")
    client = OpenAI(api_key=key)

    try:
        response = client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": _build_user_message(source_file, type_defs, fn_slices),
                },
            ],
            response_format=AuditReport,
            temperature=0.1,
        )
        report = response.choices[0].message.parsed
        if not report:
            console.print(
                f"[bold red]ERROR:[/] Model refusal: {response.choices[0].message.refusal}"
            )
            sys.exit(1)
        return report
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]ERROR:[/] OpenAI request failed: {exc}")
        sys.exit(1)


def _run_audit_gemini(
    source_file: str, type_defs: list[str], fn_slices: list[dict]
) -> AuditReport:
    """Run the audit against Google Gemini using the unified SDK."""
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        console.print(
            "[bold red]ERROR:[/] 'google-genai' is missing. Run 'pip install google-genai'."
        )
        sys.exit(1)

    key, model, _ = _get_api_config("gemini")
    client = genai.Client(api_key=key)
    config = types.GenerateContentConfig(
        temperature=0.1,
        response_mime_type="application/json",
        response_schema=AuditReport,
        system_instruction=_SYSTEM_PROMPT,
    )

    try:
        response = client.models.generate_content(
            model=model,
            contents=_build_user_message(source_file, type_defs, fn_slices),
            config=config,
        )
        return AuditReport(**json.loads(response.text))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]ERROR:[/] Gemini request failed: {exc}")
        sys.exit(1)


# Provider registry — add new backends here by mapping a key to a _ProviderFn.
# The key must match what the user sets in LLM_PROVIDER inside .env.
_PROVIDERS: dict[str, _ProviderFn] = {
    "openai": _run_audit_openai,
    "gemini": _run_audit_gemini,
}


def run_audit(
    source_file: str, type_defs: list[str], fn_slices: list[dict]
) -> AuditReport:
    """
    Dispatch the analysis to the configured LLM backend.

    Reads the ``LLM_PROVIDER`` environment variable (case-insensitive) and
    routes the call to the matching entry in ``_PROVIDERS``.

    Args:
        source_file: Path to the source file, forwarded to the provider.
        type_defs:   Extracted type definitions (structs, typedefs, etc).
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

    return _PROVIDERS[provider](source_file, type_defs, fn_slices)


# ─────────────────────────────────────────────────────────────────────────────
# §5  Rich Terminal UI
# ─────────────────────────────────────────────────────────────────────────────

# (Rich style string, display label) keyed by severity.
# Centralised here so colors and icons are consistent across every panel.
_SEVERITY_STYLES: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("bold white on red", "🔴 CRITICAL"),
    Severity.HIGH: ("bold red", "🟠 HIGH"),
    Severity.MEDIUM: ("bold yellow", "🟡 MEDIUM"),
    Severity.LOW: ("bold blue", "🔵 LOW"),
    Severity.INFO: ("bold dim", "⚪ INFO"),
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

    return Group(
        _severity_text(finding.severity), Text(""), trace_table, Text(""), rec_text
    )


def render_report(report: AuditReport) -> None:
    """
    Render a completed ``AuditReport`` to the terminal using Rich.

    Prints a header rule, then either a clean "no findings" panel or an
    overview banner followed by individual styled panels per finding.

    Args:
        report: The ``AuditReport`` returned by ``run_audit``.
    """
    console.print()
    console.print(
        Rule(
            f"[bold cyan]ASTrace AI[/] — [italic]{report.file_analysed}[/]",
            style="cyan",
        )
    )

    # Early exit with a clean result if the LLM found no issues.
    if not report.findings:
        console.print(
            Panel(
                f"[bold green]✔  No findings.[/]\n\n{report.overall_summary}",
                title="[bold green]Audit Result[/]",
                border_style="green",
            )
        )
        return

    # ── Summary banner ──
    # Aggregate all findings by severity for a quick top-level overview.
    sev_counts: dict[str, int] = {}
    for f in report.findings:
        label = _SEVERITY_STYLES[f.severity][1]  # e.g. "🟠 HIGH"
        sev_counts[label] = sev_counts.get(label, 0) + 1

    # A compact two-column table: severity icon | count.
    summary_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary_table.add_column(style="bold")
    summary_table.add_column()
    for label, count in sev_counts.items():
        summary_table.add_row(label, str(count))

    # The panel body now contains both the summary table and the LLM's text description.
    summary_group = Group(
        summary_table, Text("\n" + report.overall_summary, style="cyan")
    )

    console.print(
        Panel(
            summary_group,
            title="[bold]Finding Summary[/]",
            border_style="cyan",
        )
    )

    # ── Individual finding panels ──
    for idx, finding in enumerate(report.findings, start=1):
        # Compose the panel title from multiple styled text segments.
        header = Text()
        header.append(f"#{idx}  ", style="bold dim")
        header.append(f"{_severity_text(finding.severity)}  ")
        header.append(finding.vulnerability_type, style="bold")
        header.append(f"  in  {finding.function_name}()", style="italic dim")

        console.print()
        console.print(
            Panel(
                _build_finding_renderable(finding),
                title=str(header),
                # Pull the first word from the severity style (e.g. "bold red" → "bold") for border color.
                border_style=_SEVERITY_STYLES[finding.severity][0].split(" ")[0],
            )
        )

    console.print()
    console.print(Rule(style="dim"))
    console.print(
        f"[dim]Audit complete – {len(report.findings)} finding(s) reported.[/]\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# §6  Entry Point
# ─────────────────────────────────────────────────────────────────────────────


def run_doctor() -> bool:
    """
    Verify the application environment and print a status report.
    Returns True if all critical dependencies are met.
    """
    all_ok = True

    # 1. libclang
    with console.status("[dim]Checking libclang...[/]"):
        lib_path = find_libclang()
    if lib_path:
        console.print(
            f"  [green]✔[/] [bold]libclang:[/] Found at [italic]{lib_path}[/]"
        )
    else:
        console.print("  [red]✘[/] [bold red]libclang:[/] Not found.")
        console.print(
            "      [dim]Action: Install `libllvm` or `clang` package, or set `CLANG_LIBRARY_PATH`. [/]"
        )
        all_ok = False

    # 2. LLM Providers
    provider = os.environ.get("LLM_PROVIDER", "openai").lower().strip()
    key_name = "OPENAI_API_KEY" if provider == "openai" else "GEMINI_API_KEY"
    api_key = os.environ.get(key_name)

    if api_key:
        console.print(
            f"  [green]✔[/] [bold]LLM Provider:[/] {provider} (Key detected: {key_name})"
        )
    else:
        console.print(
            f"  [yellow]⚠[/] [bold yellow]LLM Provider:[/] {provider} (Key missing: {key_name})"
        )
        console.print(f"      [dim]Action: Set `{key_name}` in your .env file.[/]")
        all_ok = False

    # 3. Python Packages
    deps = {
        "clang": "clang",
        "openai": "openai",
        "google-genai": "google.genai",
        "pydantic": "pydantic",
        "rich": "rich",
        "python-dotenv": "dotenv",
    }
    missing = []
    for label, import_name in deps.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(label)

    if not missing:
        console.print(
            f"  [green]✔[/] [bold]Python Deps:[/] All {len(deps)} core packages installed."
        )
    else:
        console.print(
            f"  [red]✘[/] [bold red]Python Deps:[/] Missing: {', '.join(missing)}"
        )
        console.print("      [dim]Action: Run `pip install -r requirements.txt`[/]")
        all_ok = False

    console.print()
    if all_ok:
        console.print("[bold green]OVERALL STATUS: Ready to audit.[/]")
    else:
        console.print("[bold red]OVERALL STATUS: Environment incomplete.[/]")

    return all_ok


def main() -> None:
    """
    Enhanced entry point for the ASTrace AI security auditor.
    """
    parser = ArgumentParser(description="ASTrace AI — AST-Aware C/C++ Security Auditor")
    parser.add_argument(
        "file", nargs="?", help="Path to the C/C++ source file to audit"
    )
    parser.add_argument(
        "--check", action="store_true", help="Run environment diagnostic check"
    )
    parser.add_argument("--version", action="version", version="ASTrace AI v0.1.0-poc")
    args = parser.parse_args()

    # Feature: Environment Check
    if args.check:
        sys.exit(0 if run_doctor() else 1)

    # Validate Positional Argument
    if not args.file:
        parser.print_help()
        sys.exit(1)

    source_path = args.file
    if not Path(source_path).is_file():
        console.print(f"[bold red]ERROR:[/] File not found: [italic]{source_path}[/]")
        sys.exit(1)

    # ── Stage 1: Parse & slice ──
    with console.status(
        "[bold cyan]Parsing AST and slicing risky functions…[/]", spinner="dots"
    ):
        type_defs, fn_slices = slice_risky_functions(source_path)

    # If the slicer finds nothing, the file has no memory-management code to audit.
    if not fn_slices:
        console.print(
            Panel(
                "[bold green]✔  No high-risk code patterns found.[/]\n"
                "The file does not appear to contain memory management, "
                "pointer arithmetic, or array subscript operations.",
                title="[bold green]Audit Result[/]",
                border_style="green",
            )
        )
        return

    console.print(
        f"[cyan]AST slicer found [bold]{len(fn_slices)}[/] function(s) containing high-risk operations.[/]"
    )
    if type_defs:
        console.print(
            f"  [dim]→[/] Extracted [bold]{len(type_defs)}[/] global type definition(s)."
        )
    for fn in fn_slices:
        console.print(
            f"  [dim]→[/] [bold]{fn['name']}[/]()  "
            f"[dim](lines {fn['start_line']}–{fn['end_line']}, ops: {', '.join(fn['risk_ops'])})[/]"
        )

    # ── Stage 2: LLM analysis ──
    with console.status(
        "[bold cyan]Analysing with LLM (Logic Trace mode)…[/]", spinner="dots"
    ):
        report = run_audit(source_path, type_defs, fn_slices)

    # ── Stage 3: Render ──
    render_report(report)


if __name__ == "__main__":
    main()
