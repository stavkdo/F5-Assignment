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

# --- the JWT report (fixed in its own commit, Phase 3f) -------------------------------

@gap("3f", "jwt pattern uses base64 (+/=) but JWTs use base64url (-_)")
@pytest.mark.parametrize("secret_part", ["_adQssw5c", "dBjftJeZ4CVP"])
def test_base64url_jwt_is_fully_redacted(redactor, secret_part):
    text = (
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    assert secret_part not in redact_body(redactor, text)

@gap("3f", "jwt pattern retries from every 'eyJ' and rescans to the end: O(n^2) on hostile input")
def test_jwt_rule_is_linear_on_hostile_input(redactor):
    import time

    start = time.perf_counter()
    redact_body(redactor, "eyJ" * 20_000)  # 60 KB: about 2.5 s today, milliseconds once fixed
    assert time.perf_counter() - start < 0.5


# --- accepted limitations (documented, not planned) ----------------------------------

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
