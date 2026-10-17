"""Golden-file tests: real sample lines in, hand-checked redacted lines out.

basic_input.ndjson holds the happy-path lines 2, 3, 5, 7, 9, 26, 27, 32, 40, 46, 47, 48 and 49
of input.ndjson (Phase 2). sample_expected.ndjson is the output for the whole of input.ndjson.
Until the Phase 3f fix it left out lines 11, 15 and 16, whose JWTs leaked: a golden file must
not bless a leak.
"""

from conftest import ROOT, run_stream

FIXTURES = ROOT / "tests" / "fixtures"


def read_lines(name):
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def test_basic_fixture_matches_expected_output(redactor):
    out, err, stats = run_stream(redactor, (FIXTURES / "basic_input.ndjson").read_bytes())
    expected = read_lines("basic_expected.ndjson")
    assert out == expected
    assert (stats.read, stats.redacted, sum(stats.errors.values())) == (len(expected), len(expected), 0)
    assert err == ""


def test_basic_fixture_counts(redactor):
    run_stream(redactor, (FIXTURES / "basic_input.ndjson").read_bytes())
    assert +redactor.counts == {
        "auth-headers": 1,
        "api-key-names": 3,
        "secret-fields": 6,
        "card-number-fields": 1,
        "email": 9,
        "credit-card": 5,
        "api-key-prefix": 1,
    }


def test_sample_fixture_matches_expected_output(redactor):
    out, err, stats = run_stream(redactor, (ROOT / "input.ndjson").read_bytes())
    assert out == read_lines("sample_expected.ndjson")
    assert (stats.read, stats.redacted, stats.blank) == (50, 43, 2)
    assert dict(stats.errors) == {"invalid JSON": 3, "not a JSON object": 2}
    assert err.splitlines() == [
        "redactor: line 20: invalid JSON",
        "redactor: line 21: invalid JSON",
        "redactor: line 23: not a JSON object",
        "redactor: line 24: not a JSON object",
        "redactor: line 50: invalid JSON",
    ]


def test_sample_fixture_counts(redactor):
    run_stream(redactor, (ROOT / "input.ndjson").read_bytes())
    assert +redactor.counts == {
        "auth-headers": 9,
        "api-key-names": 7,
        "secret-fields": 13,
        "card-number-fields": 7,
        "cvv-fields": 1,
        "pii-fields": 3,
        "email": 30,
        "jwt": 4,  # line 11: 1, line 15: 2, line 16: 1
        "credit-card": 16,
        "api-key-prefix": 2,
    }
