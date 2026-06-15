"""PHISHCHECK command-line interface.

Subcommands:
  url    <url>        score a single URL
  email  [path|-]     score a raw RFC-822 email (file or stdin)

Exit codes: 0 clean, 2 suspicious findings, 3 high-risk findings,
            1 usage/IO error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import score_url, score_email, Verdict

_EXIT = {"clean": 0, "suspicious": 2, "high": 3}


def _render_table(v: Verdict) -> str:
    lines = [
        f"target : {v.target}",
        f"verdict: {v.verdict.upper()}  (score {v.score})",
        "signals:",
    ]
    if not v.signals:
        lines.append("  (none)")
    for name, weight, reason in sorted(v.signals, key=lambda s: -s[1]):
        lines.append(f"  [{weight:>3}] {name:<22} {reason}")
    return "\n".join(lines)


def _emit(v: Verdict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(v.to_dict(), indent=2))
    else:
        print(_render_table(v))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Defensive phishing-signal scoring for URLs and emails "
                    "(analysis/triage only, no network).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json"), default="table",
                   help="output format (default: table)")
    sub = p.add_subparsers(dest="command", required=True)

    pu = sub.add_parser("url", help="score a single URL")
    pu.add_argument("url", help="URL or bare hostname to score")

    pe = sub.add_parser("email", help="score a raw RFC-822 email")
    pe.add_argument("path", nargs="?", default="-",
                    help="path to .eml file, or '-' for stdin (default)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "url":
            if not args.url.strip():
                print("error: URL argument must not be blank", file=sys.stderr)
                return 1
            verdict = score_url(args.url)
        elif args.command == "email":
            if args.path == "-":
                raw = sys.stdin.read()
            else:
                with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            if not raw.strip():
                print("error: empty email input", file=sys.stderr)
                return 1
            verdict = score_email(raw)
        else:  # pragma: no cover - argparse enforces choices
            parser.error("unknown command")
            return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure — {exc}", file=sys.stderr)
        return 1

    _emit(verdict, args.format)
    return _EXIT[verdict.verdict]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
