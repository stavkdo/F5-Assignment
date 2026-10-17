import io
import json
import subprocess
import sys

from conftest import ROOT
from redactor.cli import format_summary, redact_stream


def test_redact_stream_skips_bad_lines_without_leaking(redactor):
    lines = [
        '{"body":{"password":"hunter2"}}\n',
        "WARN login failed for erin@example.com\n",
        '{"body":{"email":"a@b.com"}}\n',
    ]
    out, err = io.StringIO(), io.StringIO()
    stats = redact_stream(redactor, lines, out, err)

    assert stats == {"read": 3, "written": 2, "skipped": 1}
    assert out.getvalue().splitlines() == [
        '{"body":{"password":"****"}}',
        '{"body":{"email":"fb98d44ad7501a959f3f4f4a3f004fe2d9e581ea6207e218c4b02c08a4d75adf"}}',
    ]
    assert err.getvalue() == "redactor: line 2: skipped: invalid JSON\n"


def test_summary_lists_every_rule(redactor):
    redact_stream(redactor, ['{"body":{"password":"x"}}'], io.StringIO(), io.StringIO())
    summary = format_summary(redactor, {"read": 1, "written": 1, "skipped": 0})
    assert summary.splitlines()[0] == "redactor: 1 lines read, 1 written, 0 skipped"
    assert "secret-fields" in summary and "credit-card" in summary


def run_cli(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "redactor", *args],
        cwd=ROOT, input=stdin, capture_output=True, encoding="utf-8",
    )


def test_cli_on_sample_file():
    result = run_cli("--rules", "rules.yaml", "input.ndjson")
    assert result.returncode == 0
    out_lines = result.stdout.splitlines()
    assert out_lines  # something was written
    for line in out_lines:
        json.loads(line)  # every output line is valid JSON
    # The plain-text log line (input line 21) must not leak into stdout or stderr.
    assert "erin@example.com" not in result.stdout + result.stderr
    assert "lines read" in result.stderr


def test_cli_reads_stdin():
    result = run_cli("--rules", "rules.yaml", stdin='{"body":{"password":"hunter2"}}\n')
    assert result.returncode == 0
    assert result.stdout == '{"body":{"password":"****"}}\n'


def test_cli_fails_on_missing_rules():
    result = run_cli("--rules", "does-not-exist.yaml", "input.ndjson")
    assert result.returncode == 2
    assert result.stdout == ""  # nothing passes through unredacted
    assert "cannot read rules file" in result.stderr
