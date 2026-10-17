import json

import pytest

from redactor.actions import sha256
from redactor.engine import LineError


def body_of(redactor, body):
    return redactor.redact_record({"body": body})["body"]


# --- value rules on a single string -------------------------------------------------

def test_email_in_sentence_is_hashed(redactor):
    out = body_of(redactor, "contact dave@example.com today")
    assert out == f"contact {sha256('dave@example.com')} today"
    assert redactor.counts["email"] == 1


def test_card_in_sentence_is_partially_masked(redactor):
    assert body_of(redactor, "order 4111111111111111 paid") == "order ************1111 paid"
    assert redactor.counts["credit-card"] == 1


def test_non_luhn_number_is_untouched(redactor):
    text = "order ref 4111111111111112 was shipped"
    assert body_of(redactor, text) == text
    assert redactor.counts["credit-card"] == 0


def test_two_matches_in_one_string_are_both_counted(redactor):
    out = body_of(redactor, "a@x.com and b@x.com")
    assert out == f"{sha256('a@x.com')} and {sha256('b@x.com')}"
    assert redactor.counts["email"] == 2


def test_api_key_prefix_in_text_is_masked(redactor):
    assert redactor._redact_string("key: sk_live_9fA2kLmQ7x.") == "key: ****."


def test_plain_text_is_unchanged(redactor):
    assert redactor._redact_string("nothing to see here") == "nothing to see here"


# --- recursive walker ---------------------------------------------------------------

def test_nested_dicts(redactor):
    out = body_of(redactor, {"a": {"b": {"c": {"email": "deep@example.com"}}}})
    assert out == {"a": {"b": {"c": {"email": sha256("deep@example.com")}}}}


def test_lists_of_dicts_and_nested_lists(redactor):
    out = body_of(redactor, {"items": [{"email": "a@x.com"}, [["b@x.com"]], 42, None]})
    assert out == {"items": [{"email": sha256("a@x.com")}, [[sha256("b@x.com")]], 42, None]}


def test_non_string_scalars_are_untouched(redactor):
    body = {"amount": 10.5, "ok": True, "missing": None, "count": 3}
    assert body_of(redactor, body) == body


def test_input_is_not_mutated(redactor):
    record = {"body": {"password": "hunter2"}}
    redactor.redact_record(record)
    assert record == {"body": {"password": "hunter2"}}


# --- key rules ----------------------------------------------------------------------

@pytest.mark.parametrize("header", ["Authorization", "authorization", "AUTHORIZATION"])
def test_auth_header_is_masked_in_any_case(redactor, header):
    out = redactor.redact_record({"headers": {header: "Bearer abc"}})
    assert out["headers"] == {header: "****"}


def test_api_key_header_is_hashed(redactor):
    out = redactor.redact_record({"headers": {"X-Api-Key": "sk_live_abc123"}})
    # The key rule wins, so the api-key-prefix value rule never sees the value.
    assert out["headers"] == {"X-Api-Key": sha256("sk_live_abc123")}
    assert redactor.counts["api-key-names"] == 1
    assert redactor.counts["api-key-prefix"] == 0


def test_secret_field_is_masked(redactor):
    assert body_of(redactor, {"user": {"password": "hunter2"}}) == {"user": {"password": "****"}}


def test_card_number_field_is_partial(redactor):
    assert body_of(redactor, {"card_number": "378282246310005"}) == {"card_number": "***********0005"}


def test_cvv_key_is_removed(redactor):
    assert body_of(redactor, {"number": "x", "cvv": "123"}) == {"number": "x"}
    assert redactor.counts["cvv-fields"] == 1


def test_body_scoped_rule_does_not_fire_in_headers(redactor):
    # secret-fields has scope: body, so a header called "token" is not a key-rule match.
    out = redactor.redact_record({"headers": {"token": "abc"}})
    assert out["headers"] == {"token": "abc"}


def test_key_rule_on_nested_value_masks_each_leaf(redactor):
    # Phase 3b: the structure is kept, every scalar under the key is redacted.
    assert body_of(redactor, {"token": {"a": 1, "b": ["x"]}}) == {"token": {"a": "****", "b": ["****"]}}


# --- whole record -------------------------------------------------------------------

def test_response_headers_and_body_are_redacted(redactor):
    out = redactor.redact_record({
        "response": {"status": 200, "headers": {"Set-Cookie": "session=abc"}, "body": {"email": "x@y.com"}},
    })
    assert out["response"] == {"status": 200, "headers": {"Set-Cookie": "****"}, "body": {"email": sha256("x@y.com")}}


def test_metadata_fields_without_secrets_are_unchanged(redactor):
    record = {"ts": "2025-01-15T10:00:00Z", "method": "GET", "path": "/v1/me"}
    assert redactor.redact_record(record) == record


def test_unknown_top_level_fields_are_redacted_too(redactor):
    # Default deny: a field the engine doesn't know is walked as body data, not passed through.
    out = redactor.redact_record({"user": "a@b.com", "query": {"password": "x"}})
    assert out == {"user": sha256("a@b.com"), "query": {"password": "****"}}


def test_redact_line_sample_line_1(redactor):
    line = (
        '{"ts":"2025-01-15T10:00:00Z","method":"POST","path":"/v1/users",'
        '"headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig","X-Api-Key":"sk_live_abc123","Content-Type":"application/json"},'
        '"body":{"user":{"email":"a@b.com","card":{"number":"4111111111111111","cvv":"123"}}},'
        '"response":{"status":200,"headers":{"Content-Type":"application/json"},"body":null}}'
    )
    expected = (
        '{"ts":"2025-01-15T10:00:00Z","method":"POST","path":"/v1/users",'
        f'"headers":{{"Authorization":"****","X-Api-Key":"{sha256("sk_live_abc123")}","Content-Type":"application/json"}},'
        f'"body":{{"user":{{"email":"{sha256("a@b.com")}","card":{{"number":"************1111"}}}}}},'
        '"response":{"status":200,"headers":{"Content-Type":"application/json"},"body":null}}'
    )
    assert redactor.redact_line(line) == expected
    assert dict(redactor.counts) == {
        "auth-headers": 1, "api-key-names": 1, "email": 1, "credit-card": 1, "cvv-fields": 1,
    }


def test_redact_line_keeps_unicode_readable(redactor):
    out = redactor.redact_line('{"body":{"city":"Zürich","note":"名前 😀"}}')
    assert json.loads(out) == {"body": {"city": "Zürich", "note": "名前 😀"}}
    assert "Zürich" in out


@pytest.mark.parametrize("line, reason", [
    ('{"body": {"email": "trunc@exam', "invalid JSON"),
    ("2025-01-15 WARN user=erin@example.com", "invalid JSON"),
    ("", "invalid JSON"),
    ("42", "not a JSON object"),
    ('["a@b.com"]', "not a JSON object"),
])
def test_bad_lines_raise_line_error_without_content(redactor, line, reason):
    with pytest.raises(LineError) as exc:
        redactor.redact_line(line)
    assert str(exc.value) == reason
