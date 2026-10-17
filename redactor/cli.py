"""Command line entry point.

    redactor [--rules rules.yaml] [--max-line-bytes N] [--hmac] [--watch-rules] [input-file]
    redactor --serve [--addr :8080] [--rules rules.yaml] [--max-line-bytes N] [--hmac]
"""

import argparse
import os
import sys

from redactor.engine import Redactor
from redactor.reload import RulesWatcher
from redactor.rules import HMAC_KEY_ENV, RulesError, hmac_key_from_env, read_rules_file, with_hmac_key
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
    parser.add_argument(
        "--hmac", action="store_true",
        help=f"hash with HMAC-SHA256 instead of plain SHA-256; the secret key comes from {HMAC_KEY_ENV}",
    )
    parser.add_argument(
        "--watch-rules", action="store_true",
        help="re-read the rules file while running and switch to new rules if they are valid (CLI only)",
    )
    args = parser.parse_args(argv)
    if args.serve and args.input:
        parser.error("an input file can't be used with --serve")
    if args.serve and args.watch_rules:
        parser.error("--watch-rules works in CLI mode only (see the README)")

    # Rules are loaded before anything else, also before the service opens its port: if they
    # can't be loaded, the service never starts, so it can't pass traffic through unredacted.
    # The same for the --hmac key: without it we refuse to run rather than hash with plain SHA-256.
    try:
        rules, loaded_from = read_rules_file(args.rules)
        hmac_key = hmac_key_from_env() if args.hmac else None
    except RulesError as e:
        print(f"redactor: {e}", file=sys.stderr)
        return 2

    def prepare(new_rules):
        return with_hmac_key(new_rules, hmac_key) if hmac_key is not None else new_rules

    rules = prepare(rules)

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
    before_line = None
    if args.watch_rules:
        before_line = RulesWatcher(args.rules, loaded_from, redactor, sys.stderr, prepare).check

    try:
        if args.input:
            try:
                source = open(args.input, "rb")
            except OSError as e:
                print(f"redactor: cannot read {args.input}: {e.strerror}", file=sys.stderr)
                return 2
            with source:
                stats = redact_stream(redactor, source, sys.stdout, sys.stderr, args.max_line_bytes, before_line)
        else:
            stats = redact_stream(redactor, sys.stdin.buffer, sys.stdout, sys.stderr, args.max_line_bytes, before_line)
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
