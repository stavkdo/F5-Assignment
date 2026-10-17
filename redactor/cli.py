"""Command line entry point.

    redactor [--rules rules.yaml] [--max-line-bytes N] [input-file]
    redactor --serve [--addr :8080] [--rules rules.yaml] [--max-line-bytes N]
"""

import argparse
import os
import sys

from redactor.engine import Redactor
from redactor.rules import RulesError, load_rules
from redactor.stream import DEFAULT_MAX_LINE_BYTES, format_summary, redact_stream


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redactor", description="Redact sensitive data from NDJSON traffic logs.")
    parser.add_argument("--rules", default="rules.yaml", help="path to the rules YAML file (default: rules.yaml)")
    parser.add_argument(
        "--max-line-bytes", type=_positive_int, default=DEFAULT_MAX_LINE_BYTES,
        help=f"longer lines are replaced by an error record (default: {DEFAULT_MAX_LINE_BYTES})",
    )
    parser.add_argument("input", nargs="?", help="NDJSON input file (default: stdin)")
    parser.add_argument("--serve", action="store_true", help="run as an HTTP service instead (POST /redact)")
    parser.add_argument("--addr", default=":8080", help="service address, [host]:port (default: :8080)")
    args = parser.parse_args(argv)
    if args.serve and args.input:
        parser.error("an input file can't be used with --serve")

    # Rules are loaded before anything else, also before the service opens its port: if they
    # can't be loaded, the service never starts, so it can't pass traffic through unredacted.
    try:
        rules = load_rules(args.rules)
    except RulesError as e:
        print(f"redactor: {e}", file=sys.stderr)
        return 2

    if args.serve:
        from redactor.service import parse_addr, serve  # the CLI alone doesn't need the web stack

        try:
            parse_addr(args.addr)
        except ValueError as e:
            print(f"redactor: {e}", file=sys.stderr)
            return 2
        serve(rules, args.addr, args.max_line_bytes)
        return 0

    # Always UTF-8 with "\n" line endings, whatever the platform default is (e.g. cp1252 on Windows).
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    redactor = Redactor(rules)

    try:
        if args.input:
            try:
                source = open(args.input, "rb")
            except OSError as e:
                print(f"redactor: cannot read {args.input}: {e.strerror}", file=sys.stderr)
                return 2
            with source:
                stats = redact_stream(redactor, source, sys.stdout, sys.stderr, args.max_line_bytes)
        else:
            stats = redact_stream(redactor, sys.stdin.buffer, sys.stdout, sys.stderr, args.max_line_bytes)
        sys.stdout.flush()
    except BrokenPipeError:
        # Whoever read our output went away (e.g. `redactor big.ndjson | head`). Not worth a traceback.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1
    except KeyboardInterrupt:
        return 130
    except OSError as e:
        print(f"redactor: I/O error: {e.strerror}", file=sys.stderr)
        return 1

    print(format_summary(redactor, stats), file=sys.stderr)
    return 0


def _positive_int(text: str) -> int:
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value
