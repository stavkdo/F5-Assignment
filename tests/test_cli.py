import json
import subprocess
import sys

from conftest import ROOT, run_stream
from redactor.actions import sha256
from redactor.stream import format_summary


def test_redact_stream_replaces_bad_lines_without_leaking(redactor):
    data = '{"body":{"password":"hunter2"}}\nWARN login failed for erin@example.com\n{"body":{"email":"a@b.com"}}\n'
    out, err, stats = run_stream(redactor, data)

    assert out == [
        '{"body":{"password":"****"}}',
        '{"redactor_error":{"line":2,"reason":"invalid JSON"}}',
        f'{{"body":{{"email":"{sha256("a@b.com")}"}}}}',
    ]
    assert err == "redactor: line 2: invalid JSON\n"
    assert (stats.read, stats.redacted, dict(stats.errors)) == (3, 2, {"invalid JSON": 1})


def test_summary_lists_every_rule_and_error_reason(redactor):
    _, _, stats = run_stream(redactor, '{"body":{"password":"x"}}\n42\n\n')
    summary = format_summary(redactor, stats)
    assert summary.splitlines()[0] == (
        "redactor: 3 lines read: 1 redacted, 1 replaced by an error record, 1 blank skipped"
    )
    assert "errors: not a JSON object 1" in summary
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
    assert len(out_lines) == 48  # 50 lines minus the 2 blank ones
    for line in out_lines:
        json.loads(line)  # every output line is valid JSON
    # The plain-text log line (input line 21) must not leak into stdout or stderr.
    assert "erin@example.com" not in result.stdout + result.stderr
    assert "50 lines read: 43 redacted, 5 replaced by an error record, 2 blank skipped" in result.stderr


def test_cli_reads_stdin():
    result = run_cli("--rules", "rules.yaml", stdin='{"body":{"password":"hunter2"}}\n')
    assert result.returncode == 0
    assert result.stdout == '{"body":{"password":"****"}}\n'


def test_cli_fails_on_missing_rules():
    result = run_cli("--rules", "does-not-exist.yaml", "input.ndjson")
    assert result.returncode == 2
    assert result.stdout == ""  # nothing passes through unredacted
    assert "cannot read rules file" in result.stderr


def test_cli_fails_on_missing_input():
    result = run_cli("--rules", "rules.yaml", "does-not-exist.ndjson")
    assert result.returncode == 2
    assert "cannot read does-not-exist.ndjson" in result.stderr


def test_cli_max_line_bytes_flag():
    result = run_cli("--rules", "rules.yaml", "--max-line-bytes", "20", stdin='{"body":"a@b.com and more text"}\n{}\n')
    assert result.stdout == '{"redactor_error":{"line":1,"reason":"line too long"}}\n{}\n'
    assert "a@b.com" not in result.stderr


def test_cli_rejects_a_non_positive_line_limit():
    assert run_cli("--max-line-bytes", "0", stdin="").returncode == 2
