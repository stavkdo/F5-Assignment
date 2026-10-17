"""Phase 3c: body shapes. JSON inside strings, form bodies, free text, query strings."""

import json

import pytest

from conftest import redact_body
from redactor.actions import sha256
from redactor.engine import MAX_DECODES, LineError


def body(redactor, value):
    return json.loads(redact_body(redactor, value))["body"]


# --- JSON inside a string -----------------------------------------------------------

def test_json_string_body_is_decoded_and_redacted(redactor):
    # Input line 10.
    raw = '{"email":"carol@example.com","password":"p@ssw0rd!","profile":{"card":"5555555555554444"}}'
    out = body(redactor, raw)
    assert json.loads(out) == {
        "email": sha256("carol@example.com"), "password": "****", "profile": {"card": "************4444"},
    }


def test_json_response_body_string(redactor):
    # Input line 1: the response body is a string holding {"token":"abc123"}.
    line = '{"response":{"status":200,"body":"{\\"token\\":\\"abc123\\"}"}}'
    assert redactor.redact_line(line) == '{"response":{"status":200,"body":"{\\"token\\":\\"****\\"}"}}'


def test_json_string_without_secrets_is_left_byte_for_byte(redactor):
    raw = '{"a": 1,   "b": [10.50, true]}'
    assert body(redactor, raw) == raw


def test_json_string_keeps_its_numbers_when_rewritten(redactor):
    assert body(redactor, '{"password": "x", "amount": 10.50}') == '{"password":"****","amount":10.50}'


def test_cut_off_json_string_still_has_its_secret_masked(redactor):
    # Not valid JSON, so it's free text, and the "password": "..." pair is still found.
    assert body(redactor, '{"user":"x","password":"p@ss') == '{"user":"x","password":"****'


def test_json_inside_a_header_value_uses_body_rules(redactor):
    out = redactor.redact_line(json.dumps({"headers": {"X-Data": '{"password":"x"}'}}))
    assert json.loads(out) == {"headers": {"X-Data": '{"password":"****"}'}}


def wrap_in_json_strings(value, times):
    for _ in range(times):
        value = json.dumps(value)
    return value


def test_json_nested_in_strings_up_to_the_limit_is_decoded(redactor):
    # body -> string -> string -> object: MAX_DECODES levels.
    value = wrap_in_json_strings({"password": "deep-secret"}, MAX_DECODES - 1)
    assert "deep-secret" not in redact_body(redactor, value)


def test_json_nested_deeper_than_the_limit_fails_closed(redactor):
    # Past the limit the quotes are escaped (\"password\"), so the free-text scan can't read the
    # pair either. Rather than pass it through unread, the line is refused.
    value = wrap_in_json_strings({"password": "deep-secret"}, MAX_DECODES + 2)
    with pytest.raises(LineError, match="nesting too deep"):
        redact_body(redactor, value)


# --- form-encoded ------------------------------------------------------------------

def test_form_body_is_decoded_per_pair(redactor):
    # Input line 8.
    out = body(redactor, "email=bob%40example.com&password=hunter2&card=4111111111111111&remember=on")
    assert out == f"email={sha256('bob@example.com')}&password=****&card=************1111&remember=on"


def test_form_pairs_without_secrets_keep_their_encoding(redactor):
    raw = "q=caf%C3%A9+au+lait&page=2&sort=a%2Cb"
    assert body(redactor, raw) == raw


def test_form_remove_rule_drops_the_pair(redactor):
    assert body(redactor, "number=1&cvv=123&x=y") == "number=1&x=y"


def test_base64_padding_is_not_mistaken_for_a_secret(redactor):
    # Input line 17: looks like name=value to the form check, nothing to redact.
    assert body(redactor, "UEsDBBQAAAAIAA==") == "UEsDBBQAAAAIAA=="


# --- free text ---------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("login attempt password=hunter2 for user=zed", "login attempt password=**** for user=zed"),  # line 41
    ("retry with password: hunter2 now", "retry with password: **** now"),
    ('config {"secret": "s3cr3t", "n": 1}x', 'config {"secret": "****", "n": 1}x'),
    ("Authorization: Bearer abc.def.ghi failed", "Authorization: **** failed"),
    ("bad cvv=123 given", "bad  given"),
    ("my_password=visible", "my_password=visible"),  # near miss
])
def test_key_value_pairs_in_free_text(redactor, text, expected):
    assert body(redactor, text) == expected


@pytest.mark.parametrize("text, expected", [
    # The text after "https:" looks like the value of a key "https"; the scan must still look inside it.
    ("reset link https://x.example/r?token=abc&lang=en sent", "reset link https://x.example/r?token=****&lang=en sent"),
    ("error:password=hunter2", "error:password=****"),
    ("note: secret: s3 done", "note: secret: **** done"),
])
def test_sensitive_pair_inside_another_pairs_value(redactor, text, expected):
    assert body(redactor, text) == expected


@pytest.mark.parametrize("text", ["a:" * 200_000, "password=" * 100_000, "x" * 400_000 + ":y"],
                         ids=["many-pairs", "many-sensitive-pairs", "one-long-key"])
def test_free_text_scan_is_linear_on_hostile_input(redactor, text):
    # A naive "rescan every value" fix is quadratic on these. 400 KB must stay well under a second.
    import time

    start = time.perf_counter()
    body(redactor, text)
    assert time.perf_counter() - start < 1.0


def test_plain_text_body(redactor):
    # Input line 9.
    text = "Hi team,\nplease reset the account for dave@example.com. Temporary key: sk_live_9fA2kLmQ7x. Thanks!"
    expected = f"Hi team,\nplease reset the account for {sha256('dave@example.com')}. Temporary key: ****. Thanks!"
    assert body(redactor, text) == expected


def test_html_body(redactor):
    # Input line 31.
    assert body(redactor, "<html><body>Hello hank@example.com</body></html>") == (
        f"<html><body>Hello {sha256('hank@example.com')}</body></html>"
    )


def test_binary_looking_body_passes_unchanged(redactor):
    # Input line 17.
    raw = "\u0000\u0001\u0002\ufffd\u00ff\u0000PK\u0003\u0004"
    assert body(redactor, raw) == raw


# --- URLs and the path field ---------------------------------------------------------

def test_query_string_in_path_is_redacted(redactor):
    # Input line 30.
    out = redactor.redact_line('{"method":"GET","path":"/v1/reset?token=abc123def456&email=gina%40example.com"}')
    assert json.loads(out)["path"] == f"/v1/reset?token=****&email={sha256('gina@example.com')}"


def test_full_url_in_a_value(redactor):
    out = body(redactor, {"link": "https://x.example/reset?token=abc&lang=en"})
    assert out == {"link": "https://x.example/reset?token=****&lang=en"}


def test_path_without_query_is_unchanged(redactor):
    assert redactor.redact_record({"path": "/v1/users/42"}) == {"path": "/v1/users/42"}
