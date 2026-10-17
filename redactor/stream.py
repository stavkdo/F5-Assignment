"""Line-by-line driver around the engine, shared by the CLI and the HTTP service.

Input is read as bytes, one line at a time, with a cap on the line length, so memory stays
bounded by the longest allowed line no matter how big the input is.
"""

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Iterator, TextIO

from redactor.engine import LineError, Redactor

DEFAULT_MAX_LINE_BYTES = 1024 * 1024  # 1 MiB

# More fixed reasons, next to the engine's (see engine.py).
LINE_TOO_LONG = "line too long"
INTERNAL_ERROR = "internal error"

BOM = "\N{BYTE ORDER MARK}"  # some Windows tools put it at the start of a UTF-8 file


@dataclass
class StreamStats:
    read: int = 0  # lines read, blank ones included
    redacted: int = 0  # lines written as redacted JSON
    blank: int = 0  # empty or whitespace-only lines, skipped
    invalid_utf8: int = 0  # lines whose invalid bytes were replaced with U+FFFD
    errors: Counter = field(default_factory=Counter)  # reason -> lines written as an error record


def read_lines(source: BinaryIO, max_bytes: int) -> Iterator[bytes | None]:
    """Yield each line as bytes, or None for a line longer than max_bytes.

    A too-long line is read in chunks and thrown away, so it is never held in memory whole.
    """
    while True:
        line = source.readline(max_bytes + 1)
        if not line:
            return
        if len(line) > max_bytes and not line.endswith(b"\n"):
            while line and not line.endswith(b"\n"):
                line = source.readline(64 * 1024)
            yield None
        else:
            yield line


def error_record(lineno: int, reason: str) -> str:
    """The placeholder written instead of a line we can't process: valid JSON, no line content."""
    return json.dumps({"redactor_error": {"line": lineno, "reason": reason}}, separators=(",", ":"))


class LineProcessor:
    """Turns each input line of one stream into its output line, and counts what happened.

    One per stream (a CLI run or one HTTP request), because it holds that stream's line number
    and statistics. The CLI loop and the HTTP service both feed it lines; only where the lines
    come from differs.
    """

    def __init__(self, redactor: Redactor, err: TextIO):
        self.redactor = redactor
        self.err = err
        self.stats = StreamStats()

    def process(self, raw: bytes | None) -> str | None:
        """The output line, ending in a newline, for one input line; None for a blank line.

        raw is None for a line that was longer than the limit (see read_lines).
        """
        stats = self.stats
        stats.read += 1
        lineno = stats.read
        if raw is None:
            return self._fail(lineno, LINE_TOO_LONG)
        text = self._decode(raw, lineno)
        if lineno == 1:
            text = text.removeprefix(BOM)
        if not text.strip():
            stats.blank += 1  # NDJSON readers may skip blank lines; there is nothing in them to redact
            return None
        try:
            redacted = self.redactor.redact_line(text)
        except LineError as e:
            return self._fail(lineno, str(e))
        except Exception:
            # A bug in the redactor must not stop the stream, and its traceback could hold line
            # data, so it is reported with a fixed reason like any other bad line.
            return self._fail(lineno, INTERNAL_ERROR)
        stats.redacted += 1
        return redacted + "\n"

    def _decode(self, raw: bytes, lineno: int) -> str:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            # Not str(exception): its message quotes the offending bytes.
            self.stats.invalid_utf8 += 1
            self.err.write(f"redactor: line {lineno}: invalid UTF-8 replaced with U+FFFD\n")
            return raw.decode("utf-8", errors="replace")

    def _fail(self, lineno: int, reason: str) -> str:
        # Line number and a fixed reason only, never the line content.
        self.stats.errors[reason] += 1
        self.err.write(f"redactor: line {lineno}: {reason}\n")
        return error_record(lineno, reason) + "\n"


def redact_stream(
    redactor: Redactor,
    source: BinaryIO,
    out: TextIO,
    err: TextIO,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    before_line: Callable[[], None] | None = None,
) -> StreamStats:
    """Redact NDJSON from source to out. Only one line is held in memory at a time.

    before_line runs before each line (the rules watcher). It also means the stream is live,
    so each line is flushed: whoever reads a `tail -f` shouldn't wait for a full buffer.
    """
    processor = LineProcessor(redactor, err)
    for raw in read_lines(source, max_line_bytes):
        if before_line is not None:
            before_line()
        line = processor.process(raw)
        if line is not None:
            out.write(line)
            if before_line is not None:
                out.flush()
    return processor.stats


def format_summary(redactor: Redactor, stats: StreamStats) -> str:
    error_lines = sum(stats.errors.values())
    lines = [
        f"redactor: {stats.read} lines read: {stats.redacted} redacted, "
        f"{error_lines} replaced by an error record, {stats.blank} blank skipped"
    ]
    if error_lines:
        lines.append("  errors: " + ", ".join(f"{reason} {n}" for reason, n in sorted(stats.errors.items())))
    if stats.invalid_utf8:
        lines.append(f"  lines with invalid UTF-8 repaired: {stats.invalid_utf8}")
    names = redactor.rules.names()
    # A rule removed by a reload (--watch-rules) still did its redactions, so it's still listed.
    names += [name for name in redactor.counts if name not in names]
    width = max(len(n) for n in names) if names else 0
    lines.append("  redactions per rule:")
    lines += [f"    {name:<{width}}  {redactor.counts[name]}" for name in names]
    return "\n".join(lines)
