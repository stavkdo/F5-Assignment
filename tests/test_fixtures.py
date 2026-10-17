"""Golden-file test: real sample lines in, hand-checked redacted lines out.

basic_input.ndjson holds the happy-path lines 2, 3, 5, 7, 9, 26, 27, 32, 40, 46, 47, 48 and 49
of input.ndjson. basic_expected.ndjson is what the redactor must print for them.
"""

import io

from conftest import ROOT
from redactor.cli import redact_stream

FIXTURES = ROOT / "tests" / "fixtures"


def read_lines(name):
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def test_basic_fixture_matches_expected_output(redactor):
    out, err = io.StringIO(), io.StringIO()
    stats = redact_stream(redactor, read_lines("basic_input.ndjson"), out, err)

    expected = read_lines("basic_expected.ndjson")
    assert out.getvalue().splitlines() == expected
    assert stats == {"read": len(expected), "written": len(expected), "skipped": 0}
    assert err.getvalue() == ""


def test_basic_fixture_counts(redactor):
    redact_stream(redactor, read_lines("basic_input.ndjson"), io.StringIO(), io.StringIO())
    assert dict(redactor.counts) == {
        "auth-headers": 1,
        "api-key-names": 3,
        "secret-fields": 6,
        "card-number-fields": 1,
        "email": 9,
        "credit-card": 5,
        "api-key-prefix": 1,
    }
