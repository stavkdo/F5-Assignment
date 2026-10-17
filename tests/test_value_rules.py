"""Phase 3d: value-rule details."""

import json

import pytest

from conftest import redact_body
from redactor.actions import sha256


def text_out(redactor, text):
    return json.loads(redact_body(redactor, text))["body"]


@pytest.mark.parametrize("card, masked", [
    ("4111 1111 1111 1111", "***************1111"),  # input line 1
    ("5555-5555-5555-4444", "***************4444"),  # input line 6
    ("3782 822463 10005", "*************0005"),  # Amex 4-6-5, input line 36
    ("3056 930902 5904", "************5904"),  # Diners 4-6-4
    ("30569309025904", "**********5904"),  # Diners, no separators
    ("6011111111111117", "************1117"),  # Discover
])
def test_cards_in_all_printed_layouts(redactor, card, masked):
    assert text_out(redactor, f"please charge {card} today") == f"please charge {masked} today"


def test_digit_before_a_grouped_card_does_not_hide_it(redactor):
    # A naive (\d[ -]?){12,18}\d would start at the "1", fail Luhn, and leak the card.
    assert text_out(redactor, "id 1 4111 1111 1111 1111") == "id 1 ***************1111"


@pytest.mark.parametrize("text", [
    "order ref 4111111111111112 was shipped",  # 16 digits, fails Luhn (input line 4)
    "request id 1705312800123456 took 12ms",  # microsecond timestamp (input line 35)
    "order 12345678901234567890",  # 20 digits: too long to be a card
    "ts 2025-01-15 10:00:00",
])
def test_numbers_that_are_not_cards_stay(redactor, text):
    assert text_out(redactor, text) == text
    assert redactor.counts["credit-card"] == 0


def test_card_stored_as_a_json_number_under_any_key(redactor):
    # Integer literals go through the value rules too. Only a redacted number becomes a string.
    out = redactor.redact_line('{"body":{"amount":4111111111111111,"n":[5555555555554444]}}')
    assert out == '{"body":{"amount":"************1111","n":["************4444"]}}'
    assert redactor.counts["credit-card"] == 2


def test_integers_that_are_not_cards_keep_their_type(redactor):
    # Fails Luhn (line 35's timestamp), too long (line 28's order id), small, negative, float.
    line = '{"body":{"ts_us":1705312800123456,"order_id":12345678901234567890,"n":42,"neg":-4111111111111111,"f":4111111111111111.0}}'
    assert redactor.redact_line(line) == line


def test_a_luhn_valid_id_number_becomes_a_string(redactor):
    # The documented cost: about 1 in 10 random 16-digit numbers passes Luhn, so an ID that
    # happens to be one is redacted like a card and changes type.
    assert redactor.redact_line('{"body":{"id":1705312800123452}}') == '{"body":{"id":"************3452"}}'


@pytest.mark.parametrize("literal", ["10.50", "1e3", "1.0", "12345678901234567890", "-0"])
def test_number_literals_survive_unchanged(redactor, literal):
    # Input lines 4 and 28.
    assert redactor.redact_line(f'{{"body":{{"amount":{literal}}}}}') == f'{{"body":{{"amount":{literal}}}}}'


def test_jwt_runs_before_credit_card(redactor):
    # A JWT whose middle part is all digits: the jwt rule masks the whole token first,
    # so the card rule never sees (and never counts) the digits inside it.
    assert text_out(redactor, "t eyJhbGciOiJIUzI1NiJ9.4111111111111111.c2ln end") == "t **** end"
    assert redactor.counts["jwt"] == 1
    assert redactor.counts["credit-card"] == 0


# The JWT report (Phase 3f): the tokens from input lines 11, 15 and 16 contain "-" and "_"
# (base64url), which the old pattern's base64 class stopped at.
JWT_LINE_15 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
JWT_LINE_16 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


@pytest.mark.parametrize("text, expected", [
    (f"Bearer {JWT_LINE_15}", "Bearer ****"),  # "_" in the signature: the tail used to leak
    (f"session {JWT_LINE_16} expired", "session **** expired"),  # "_" in the payload: nothing was masked
    (f'"{JWT_LINE_16}"', '"****"'),
    (f"token={JWT_LINE_16}&x=1", "token=****&x=1"),
    ("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "****"),  # unsigned (alg none): empty third part
])
def test_base64url_jwts_are_fully_masked(redactor, text, expected):
    assert text_out(redactor, text) == expected


@pytest.mark.parametrize("text", ["eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9.only-two", "keyJSON.a.b"])
def test_jwt_lookalikes_stay(redactor, text):
    assert text_out(redactor, text) == text


@pytest.mark.parametrize("body", ["eyJ" * 100_000, "_eyJ" * 100_000, "eyJa." * 100_000], ids=["eyJ", "_eyJ", "eyJa."])
def test_jwt_rule_is_linear_on_hostile_input(redactor, body):
    # The old pattern retried from every eyJ and rescanned to the end of the run: 60 KB took
    # 2.3 s. The lookbehind and the possessive ++ in rules.yaml make it one pass.
    import time

    start = time.perf_counter()
    redact_body(redactor, body)
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("text, expected", [
    ("💳4111111111111111💳", "💳************1111💳"),  # input line 46
    ("😀zed@example.com😀", f"😀{sha256('zed@example.com')}😀"),
    ("מספר כרטיס: 4111111111111111", "מספר כרטיס: ************1111"),  # RTL, input line 47
    ("名前: 田中 email tanaka@example.co.jp", f"名前: 田中 email {sha256('tanaka@example.co.jp')}"),  # line 7
])
def test_unicode_around_matches(redactor, text, expected):
    assert text_out(redactor, text) == expected


def test_escaped_characters_are_decoded_before_matching(redactor):
    # Input line 45: "@" and the first "4" are written as JSON unicode escapes.
    out = redactor.redact_line('{"body":{"contact":"alice\\u0040example.com","card":"\\u0034111111111111111"}}')
    assert json.loads(out)["body"] == {"contact": sha256("alice@example.com"), "card": "************1111"}


@pytest.mark.parametrize("body", ["x" * 300_000, "UEsDBBQAAAAIAA" * 20_000], ids=["letters", "base64"])
def test_email_rule_is_linear_on_long_runs(redactor, body):
    # The provided email pattern retried from every position of a run with no "@": O(n^2),
    # minutes for a 1 MB base64 upload. The lookbehind in rules.yaml makes it one pass.
    import time

    start = time.perf_counter()
    redact_body(redactor, body)
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("text", ["not-an-email@", "a@b", "x@y.z", "name@exa_mple.com"])
def test_email_lookalikes_stay(redactor, text):
    # Input line 29.
    assert text_out(redactor, text) == text


@pytest.mark.parametrize("text, expected", [
    ("db at postgres://admin:hunter2@db:5432/app", "db at postgres://****@db:5432/app"),
    ("db at postgres://admin:hunter2@db.internal/app", "db at postgres://****@db.internal/app"),  # before email
    ("clone https://bot:ghp_abc123@github.com/x.git", "clone https://****@github.com/x.git"),
    ("see https://user@intranet/page", "see https://user@intranet/page"),  # no password: left alone
    ("at 10:00:00 the time was a:b@c", "at 10:00:00 the time was a:b@c"),  # no "://": not a URL
])
def test_credentials_in_urls(redactor, text, expected):
    assert text_out(redactor, text) == expected


@pytest.mark.parametrize("card, masked", [
    ("４１１１１１１１１１１１１１１１", "************１１１１"),  # full-width digits
    ("٤١١١١١١١١١١١١١١١", "************١١١١"),  # Arabic-Indic digits
])
def test_cards_in_non_ascii_digits(redactor, card, masked):
    assert text_out(redactor, f"card {card}") == f"card {masked}"
