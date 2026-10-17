"""Phase 3b: key-matching details."""

import json

import pytest

from conftest import redact_body
from redactor.actions import sha256


def body(redactor, value):
    return json.loads(redact_body(redactor, value))["body"]


def headers(redactor, value):
    return json.loads(redactor.redact_line(json.dumps({"headers": value})))["headers"]


@pytest.mark.parametrize("name", ["Authorization", "authorization", "AUTHORIZATION", "aUtHoRiZaTiOn"])
def test_header_names_match_in_any_case(redactor, name):
    assert headers(redactor, {name: "Basic dXNlcjpwYXNz"}) == {name: "****"}


@pytest.mark.parametrize("name", ["x-api-key", "X-API-KEY", "ApiKey", "api_key", "api-key"])
def test_api_key_names_in_any_spelling(redactor, name):
    assert headers(redactor, {name: "demo_key_1"}) == {name: sha256("demo_key_1")}


def test_header_value_arrays_keep_their_shape(redactor):
    # Input line 31 and 33.
    out = headers(redactor, {"Set-Cookie": ["session=abc123; HttpOnly", "csrf=zzz"], "Authorization": ["Bearer abc.def.ghi"]})
    assert out == {"Set-Cookie": ["****", "****"], "Authorization": ["****"]}
    assert redactor.counts["auth-headers"] == 3


@pytest.mark.parametrize("value, expected", [
    (None, None),  # null holds no secret and keeps its type
    (False, False),
    (True, True),
    ([], []),
    ({}, {}),
    ("", "****"),
    (0, "****"),  # a number under a sensitive key becomes the masked string
    (12.5, "****"),
    ([1, None, "x"], ["****", None, "****"]),
])
def test_non_string_values_under_mask_rule(redactor, value, expected):
    assert body(redactor, {"password": value}) == {"password": expected}


def test_card_number_stored_as_a_json_number(redactor):
    # Input line 28: partial needs text, so the number becomes a string.
    out = redactor.redact_line('{"body":{"card_number":4111111111111111}}')
    assert out == '{"body":{"card_number":"************1111"}}'


def test_number_under_hash_rule_is_hashed_as_its_text(redactor):
    assert redactor.redact_line('{"body":{"api_key":0}}') == f'{{"body":{{"api_key":"{sha256("0")}"}}}}'


def test_remove_drops_the_key_whatever_its_value(redactor):
    assert body(redactor, {"cvv": {"nested": "123"}, "cvv2": None, "keep": 1}) == {"keep": 1}
    assert redactor.counts["cvv-fields"] == 2


@pytest.mark.parametrize("name", [
    "password_hint", "passwordless", "tokenizer", "secret_santa", "my_password", "x-api-keys", "cardnumbers",
])
def test_near_miss_names_are_not_redacted(redactor, name):
    assert body(redactor, {name: "visible"}) == {name: "visible"}


def test_duplicate_keys_are_both_kept_and_both_redacted(redactor):
    # Input line 25: json.loads would silently keep only the second email.
    out = redactor.redact_line('{"body":{"email":"first@example.com","email":"second@example.com"}}')
    assert out == (
        f'{{"body":{{"email":"{sha256("first@example.com")}","email":"{sha256("second@example.com")}"}}}}'
    )


def test_duplicate_sensitive_keys_are_both_masked(redactor):
    out = redactor.redact_line('{"body":{"password":"a","password":"b"}}')
    assert out == '{"body":{"password":"****","password":"****"}}'


def test_value_rules_also_apply_to_key_names(redactor):
    # A map keyed by email still contains the email.
    out = body(redactor, {"bob@example.com": {"pan": "4111111111111111"}})
    assert out == {sha256("bob@example.com"): {"pan": "************1111"}}


def test_new_pii_key_rule(redactor):
    # Input line 37: matched by field name only (there is no SSN or phone value rule).
    out = body(redactor, {"ssn": "123-45-6789", "phone": "+1 (415) 555-0132", "dob": "1990-04-12", "name": "Ivy Chen"})
    assert out == {"ssn": "****", "phone": "****", "dob": "****", "name": "Ivy Chen"}
    assert redactor.counts["pii-fields"] == 3
