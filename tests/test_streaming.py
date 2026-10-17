"""Phase 3g: streaming. Memory depends on the longest line, not on the size of the input."""

import io
import tracemalloc

from conftest import ROOT, run_stream
from redactor.engine import Redactor
from redactor.stream import read_lines, redact_stream


class RepeatingSource:
    """A file-like source that produces `count` lines on demand, without holding them all."""

    def __init__(self, lines, count):
        self.lines, self.count, self.i = lines, count, 0

    def readline(self, limit=-1):
        if self.i >= self.count:
            return b""
        line = self.lines[self.i % len(self.lines)]
        self.i += 1
        return line


class Sink:
    """Counts what is written and throws it away."""

    def __init__(self):
        self.size = 0

    def write(self, text):
        self.size += len(text)


def peak_memory(rules, count):
    sample = [line + b"\n" for line in (ROOT / "input.ndjson").read_bytes().splitlines()]
    redactor = Redactor(rules)
    tracemalloc.start()
    redact_stream(redactor, RepeatingSource(sample, count), Sink(), Sink())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def test_memory_does_not_grow_with_input_size(rules):
    small = peak_memory(rules, 500)
    large = peak_memory(rules, 5_000)
    # 10x the input: the peak may wobble a little, but it must not grow with the line count.
    assert large < small * 1.5 + 64 * 1024, (small, large)


def test_read_lines_splits_and_flags_long_lines():
    data = b"short\n" + b"x" * 50 + b"\n" + b"exactly10!\n" + b"tail"
    assert list(read_lines(io.BytesIO(data), 10)) == [b"short\n", None, b"exactly10!\n", b"tail"]


def test_long_line_at_the_end_without_newline():
    assert list(read_lines(io.BytesIO(b"ok\n" + b"y" * 30), 10)) == [b"ok\n", None]


def test_a_huge_line_is_never_held_in_memory(redactor):
    huge = b'{"body":"' + b"a" * (8 * 1024 * 1024) + b'"}\n'
    source = io.BytesIO(huge + b'{"body":{"password":"x"}}\n')
    tracemalloc.start()
    out, err = io.StringIO(), io.StringIO()
    stats = redact_stream(redactor, source, out, err, max_line_bytes=64 * 1024)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert out.getvalue().splitlines() == [
        '{"redactor_error":{"line":1,"reason":"line too long"}}',
        '{"body":{"password":"****"}}',
    ]
    assert dict(stats.errors) == {"line too long": 1}
    assert peak < 1024 * 1024, peak  # an 8 MiB line, under 1 MiB of memory


def test_line_at_the_limit_is_accepted(redactor):
    line = '{"body":"' + "a" * 100 + '"}'
    out, _, _ = run_stream(redactor, line + "\n", max_line_bytes=len(line))
    assert out == [line]
    out, _, _ = run_stream(redactor, line + "\n", max_line_bytes=len(line) - 1)
    assert out == ['{"redactor_error":{"line":1,"reason":"line too long"}}']
