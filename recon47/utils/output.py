"""
Output utilities: coloured terminal printing and report generation.
"""

import json
import sys
from datetime import datetime, timezone
from typing import Any

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _COLORAMA_AVAILABLE = True
except ImportError:  # pragma: no cover
    _COLORAMA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _c(color_code: str, text: str) -> str:
    if _COLORAMA_AVAILABLE:
        return f"{color_code}{text}{Style.RESET_ALL}"
    return text


def info(msg: str) -> None:
    """Print an informational message (cyan)."""
    print(_c(Fore.CYAN, f"[*] {msg}"))


def success(msg: str) -> None:
    """Print a success message (green)."""
    print(_c(Fore.GREEN, f"[+] {msg}"))


def warning(msg: str) -> None:
    """Print a warning message (yellow)."""
    print(_c(Fore.YELLOW, f"[!] {msg}"))


def error(msg: str) -> None:
    """Print an error message (red) to stderr."""
    print(_c(Fore.RED, f"[-] {msg}"), file=sys.stderr)


def banner() -> None:
    """Print the Recon47 ASCII banner."""
    art = r"""
  ____                      _  _  _____  ____
 |  _ \ ___  ___ ___  _ __ | || ||___  ||___  |
 | |_) / _ \/ __/ _ \| '_ \| || |   / /    / /
 |  _ <  __/ (_| (_) | | | |__   _| /    / /
 |_| \_\___|\___\___/|_| |_|  |_||_____|_____|

        Automated Web Recon & Vulnerability Scanner
    """
    if _COLORAMA_AVAILABLE:
        print(_c(Fore.MAGENTA, art))
    else:
        print(art)


def section(title: str) -> None:
    """Print a section separator with a title."""
    line = "─" * 60
    if _COLORAMA_AVAILABLE:
        print(_c(Fore.BLUE, f"\n{line}"))
        print(_c(Fore.BLUE, f"  {title}"))
        print(_c(Fore.BLUE, line))
    else:
        print(f"\n{line}")
        print(f"  {title}")
        print(line)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def save_report(results: dict[str, Any], output_path: str, fmt: str = "json") -> None:
    """
    Persist *results* to *output_path* in either ``json`` or ``txt`` format.

    Parameters
    ----------
    results:
        Full scan results dict produced by the orchestrator.
    output_path:
        File path to write. Extension is appended automatically when missing.
    fmt:
        ``"json"`` (default) or ``"txt"``.
    """
    if fmt == "json":
        if not output_path.endswith(".json"):
            output_path += ".json"
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)
    else:
        if not output_path.endswith(".txt"):
            output_path += ".txt"
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(_results_to_text(results))

    success(f"Report saved → {output_path}")


def _results_to_text(results: dict[str, Any]) -> str:
    """Convert nested results dict to a human-readable text report."""
    lines: list[str] = []
    ts = results.get("scan_time", datetime.now(timezone.utc).isoformat())
    target = results.get("target", "unknown")
    lines.append(f"Recon47 Scan Report")
    lines.append(f"Target : {target}")
    lines.append(f"Time   : {ts}")
    lines.append("=" * 60)

    for module, data in results.items():
        if module in ("target", "scan_time"):
            continue
        lines.append(f"\n[{module.upper()}]")
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"  {k}: {v}")
        elif isinstance(data, list):
            for item in data:
                lines.append(f"  - {item}")
        else:
            lines.append(f"  {data}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines) + "\n"
