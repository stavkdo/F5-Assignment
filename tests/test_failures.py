"""Phase 3a: failure handling. Never crash, never leak, always say which line and why."""

import pytest

from conftest import run_stream
from redactor.engine import MAX_DEPTH, LineError

SECRET = "erin@example.com"


@pytest.mark.parametrize("line, reason", [
    ('{"ts":"2025-01-15","body":{"email":"erin@exam', "invalid JSON"),  # truncated (input line 50)
    ("2025-01-15 10:00:20 WARN upstream timeout user=erin@example.com", "invalid JSON"),  # plain text
    ('{"body":"erin@example.com"} trailing', "invalid JSON"),
    ('{"body":NaN,"x":"erin@example.com"}', "invalid JSON"),  # Python would accept NaN; JSON doesn't
    ("42", "not a JSON object"),
    ('["erin@example.com","4111111111111111"]', "not a JSON object"),
    ('"erin@example.com"', "not a JSON object"),
    ("null", "not a JSON object"),
])
def test_bad_line_becomes_an_error_record(redactor, line, reason):
    out, err, stats = run_stream(redactor, line + "\n")
    assert out == [f'{{"redactor_error":{{"line":1,"reason":"{reason}"}}}}']
    assert err == f"redactor: line 1: {reason}\n"
    assert SECRET not in "".join(out) + err
    assert dict(stats.errors) == {reason: 1}


def test_error_record_keeps_the_input_line_number(redactor):
    out, _, _ = run_stream(redactor, '{}\n{}\nnot json\n{}\n')
    assert out == ["{}", "{}", '{"redactor_error":{"line":3,"reason":"invalid JSON"}}', "{}"]


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\r"])
def test_blank_lines_are_skipped_and_counted(redactor, blank):
    out, err, stats = run_stream(redactor, f'{{}}\n{blank}\n{{}}\n')
    assert out == ["{}", "{}"]
    assert err == ""
    assert (stats.read, stats.redacted, stats.blank) == (3, 2, 1)


@pytest.mark.parametrize("depth", [MAX_DEPTH + 10, 5000])
def test_deeply_nested_line_is_reported_not_crashed(redactor, depth):
    line = '{"body":' + "[" * depth + "]" * depth + "}"
    with pytest.raises(LineError, match="nesting too deep"):
        redactor.redact_line(line)


def test_deep_nesting_in_any_field_or_inside_a_string_is_caught(redactor):
    for line in [
        '{"ts":' + "[" * 900 + "]" * 900 + "}",  # a field outside headers/body
        '{"body":"' + "[" * 900 + "]" * 900 + '"}',  # JSON inside a string
        '{"body":{"password":' + "[" * 900 + "]" * 900 + "}}",  # under a key rule
    ]:
        with pytest.raises(LineError, match="nesting too deep"):
            redactor.redact_line(line)


def test_normal_nesting_is_fine(redactor):
    line = '{"body":' + '{"a":' * 30 + '"x@y.com"' + "}" * 30 + "}"
    assert "x@y.com" not in redactor.redact_line(line)


def test_unexpected_exception_becomes_an_internal_error_record(redactor, monkeypatch):
    def explode(text):
        raise RuntimeError(f"bug while handling {text}")  # the message holds line content

    monkeypatch.setattr(redactor, "redact_line", explode)
    out, err, stats = run_stream(redactor, '{"body":"erin@example.com"}\n')
    assert out == ['{"redactor_error":{"line":1,"reason":"internal error"}}']
    assert err == "redactor: line 1: internal error\n"
    assert SECRET not in err


def test_counts_of_a_failed_line_are_discarded(redactor):
    # The password is counted while walking, then the line fails deeper down.
    line = '{"body":{"password":"x","deep":' + "[" * 200 + "]" * 200 + "}}"
    run_stream(redactor, line + "\n")
    assert redactor.counts["secret-fields"] == 0


def test_invalid_utf8_is_repaired_and_reported(redactor):
    out, err, stats = run_stream(redactor, b'{"body":"caf\xff erin@example.com"}\n')
    assert len(out) == 1 and SECRET not in out[0]
    assert "\ufffd" in out[0]
    assert err == "redactor: line 1: invalid UTF-8 replaced with U+FFFD\n"
    assert stats.invalid_utf8 == 1


def test_utf8_byte_order_mark_on_the_first_line_is_ignored(redactor):
    out, _, _ = run_stream(redactor, b'\xef\xbb\xbf{"body":"x"}\n')
    assert out == ['{"body":"x"}']


def test_last_line_without_newline_is_processed(redactor):
    out, _, _ = run_stream(redactor, '{}\n{"body":{"password":"x"}}')
    assert out == ["{}", '{"body":{"password":"****"}}']


def test_crlf_line_endings_are_accepted(redactor):
    out, _, _ = run_stream(redactor, '{"a":1}\r\n{"b":2}\r\n')
    assert out == ['{"a":1}', '{"b":2}']
