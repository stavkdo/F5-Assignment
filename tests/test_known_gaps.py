"""Known problems in the basic redactor, written as tests that currently fail.

Each test states the behaviour we want. They are marked xfail(strict=True): pytest reports
them as "expected failures" today, and turns them into real failures the moment one starts
passing, so the marker gets removed together with the fix. The phase in each reason
refers to TASKS.md.
"""

import json

import pytest

from redactor.engine import LineError


def gap(phase, reason):
    return pytest.mark.xfail(strict=True, reason=f"{phase}: {reason}")


def redact_body(redactor, body):
    return redactor.redact_line(json.dumps({"body": body}))


# --- secrets that leak through ------------------------------------------------------

@gap("3d", "card regex \\b\\d{13,19}\\b does not allow spaces or dashes")
@pytest.mark.parametrize("card", ["4111 1111 1111 1111", "5555-5555-5555-4444", "3782 822463 10005"])
def test_card_with_separators_is_redacted(redactor, card):
    assert card not in redact_body(redactor, f"please charge {card} today")


@gap("3f", "jwt pattern uses base64 (+/=) but JWTs use base64url (-_)")
@pytest.mark.parametrize("secret_part", ["_adQssw5c", "dBjftJeZ4CVP"])
def test_base64url_jwt_is_fully_redacted(redactor, secret_part):
    text = (
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    assert secret_part not in redact_body(redactor, text)


@gap("3c", "a string body that contains JSON is not decoded, so key rules never see its keys")
@pytest.mark.parametrize("secret", ["abc123", "p@ssw0rd!"])
def test_json_inside_string_body_is_redacted(redactor, secret):
    body = '{"token":"abc123","password":"p@ssw0rd!"}'
    assert secret not in redact_body(redactor, body)


@gap("3c", "form-encoded bodies are treated as plain text")
@pytest.mark.parametrize("secret", ["hunter2", "bob%40example.com"])
def test_form_encoded_body_is_redacted(redactor, secret):
    assert secret not in redact_body(redactor, "email=bob%40example.com&password=hunter2&remember=on")


@gap("3c", "key=value pairs inside free text are not recognised")
def test_password_in_free_text_is_redacted(redactor):
    assert "hunter2" not in redact_body(redactor, {"debug": "login attempt password=hunter2 for user=zed"})


@gap("3c", "the path field is passed through untouched")
@pytest.mark.parametrize("secret", ["abc123def456", "gina%40example.com"])
def test_query_string_in_path_is_redacted(redactor, secret):
    out = redactor.redact_line('{"method":"GET","path":"/v1/reset?token=abc123def456&email=gina%40example.com"}')
    assert secret not in out


# --- robustness ---------------------------------------------------------------------

@gap("3a", "json.loads raises RecursionError, which is not caught, so the tool crashes")
def test_deeply_nested_line_does_not_crash(redactor):
    line = '{"body":' + "[" * 5000 + "]" * 5000 + "}"
    try:
        redactor.redact_line(line)
    except LineError:
        pass  # reporting the line as bad is fine; crashing is not


# --- correctness --------------------------------------------------------------------

@gap("3e", "hash is applied again to an already hashed value")
def test_redacting_twice_gives_the_same_output(redactor):
    once = redactor.redact_line('{"headers":{"X-Api-Key":"sk_live_abc123"}}')
    assert redactor.redact_line(once) == once


@gap("3d", "json.loads + json.dumps rewrite number literals")
@pytest.mark.parametrize("literal", ["10.50", "1e3"])
def test_number_literals_survive_unchanged(redactor, literal):
    assert f'"amount":{literal}' in redactor.redact_line(f'{{"body":{{"amount":{literal}}}}}')
