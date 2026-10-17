"""Command line entry point: redactor [--rules rules.yaml] [input-file]"""

import argparse
import sys
from typing import Iterable, TextIO

from redactor.engine import LineError, Redactor
from redactor.rules import RulesError, load_rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redactor", description="Redact sensitive data from NDJSON traffic logs.")
    parser.add_argument("--rules", default="rules.yaml", help="path to the rules YAML file (default: rules.yaml)")
    parser.add_argument("input", nargs="?", help="NDJSON input file (default: stdin)")
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except RulesError as e:
        print(f"redactor: {e}", file=sys.stderr)
        return 2

    # Always UTF-8 with "\n" line endings, whatever the platform default is (e.g. cp1252 on Windows).
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    redactor = Redactor(rules)

    if args.input:
        try:
            with open(args.input, encoding="utf-8", errors="replace") as f:
                stats = redact_stream(redactor, f, sys.stdout, sys.stderr)
        except OSError as e:
            print(f"redactor: cannot read {args.input}: {e.strerror}", file=sys.stderr)
            return 2
    else:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        stats = redact_stream(redactor, sys.stdin, sys.stdout, sys.stderr)

    sys.stdout.flush()
    print(format_summary(redactor, stats), file=sys.stderr)
    return 0


def redact_stream(redactor: Redactor, lines: Iterable[str], out: TextIO, err: TextIO) -> dict[str, int]:
    """Redact line by line. Only one line is held in memory at a time."""
    stats = {"read": 0, "written": 0, "skipped": 0}
    for lineno, line in enumerate(lines, start=1):
        stats["read"] += 1
        try:
            redacted = redactor.redact_line(line)
        except LineError as e:
            # Line number and our own reason only, never the line content.
            stats["skipped"] += 1
            err.write(f"redactor: line {lineno}: skipped: {e}\n")
            continue
        out.write(redacted + "\n")
        stats["written"] += 1
    return stats


def format_summary(redactor: Redactor, stats: dict[str, int]) -> str:
    names = redactor.rules.names()
    width = max(len(n) for n in names) if names else 0
    lines = [f"redactor: {stats['read']} lines read, {stats['written']} written, {stats['skipped']} skipped"]
    lines += [f"  {name:<{width}}  {redactor.counts[name]}" for name in names]
    return "\n".join(lines)
