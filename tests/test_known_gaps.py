"""Known gaps, written as tests that currently fail.

Each test states the behaviour we'd want. They are marked xfail(strict=True): pytest reports
them as "expected failures" today, and turns them into real failures the moment one starts
passing, so the marker gets removed together with the fix. Every gap here is listed under
"Known limitations" in the README. The phase in each reason refers to TASKS.md.
"""

import pytest

from conftest import redact_body


def gap(phase, reason):
    return pytest.mark.xfail(strict=True, reason=f"{phase}: {reason}")


# --- accepted limitations (documented, not planned) ----------------------------------

@gap("limit", "a JWT glued to a letter, digit, '_' or '-' isn't matched: the price of a linear jwt rule")
def test_jwt_glued_to_a_word(redactor):
    assert "dBjftJeZ4CVP" not in redact_body(
        redactor, "jwt_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )


@gap("limit", "percent-encoding is only decoded in a whole form body or URL, not inside a sentence")
def test_percent_encoded_email_in_a_sentence(redactor):
    assert "gina%40example.com" not in redact_body(redactor, "reset sent, see email=gina%40example.com for details")


@gap("limit", "HTML entities are not decoded")
def test_html_entity_encoded_email(redactor):
    assert "example.com" not in redact_body(redactor, "<p>alice&#64;example.com</p>")


@gap("limit", "base64 is not decoded: it can't be told apart from ordinary tokens")
def test_base64_encoded_password(redactor):
    # base64 of {"pw":"hunter2"}
    assert "eyJwdyI6Imh1bnRlcjIifQ" not in redact_body(redactor, "payload eyJwdyI6Imh1bnRlcjIifQ==")

@gap("limit", "no phone-number value rule: too many false positives on IDs and timestamps")
def test_phone_number_in_free_text(redactor):
    assert "555-0132" not in redact_body(redactor, "call me at +1 (415) 555-0132")

@gap("limit", "a bare value in free text ends at the first space")
def test_phone_after_a_sensitive_key_in_free_text(redactor):
    assert "555-0132" not in redact_body(redactor, "phone: +1 (415) 555-0132")

@gap("limit", "no SSN value rule: SSN detection is not in the brief (planned, see README)")
def test_ssn_in_free_text(redactor):
    assert "123-45-6789" not in redact_body(redactor, "customer ssn is 123-45-6789")

@gap("limit", "the card pattern needs one kind of separator throughout")
def test_card_with_mixed_separators(redactor):
    assert "1111-1111" not in redact_body(redactor, "card 4111 1111-1111 1111")
