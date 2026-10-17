"""Phase 3e: running the redactor on its own output changes nothing."""

import pytest

from conftest import ROOT, run_stream
from redactor.engine import Redactor


def redact_twice(rules, data):
    first, _, _ = run_stream(Redactor(rules), data)
    second, _, _ = run_stream(Redactor(rules), "\n".join(first) + "\n")
    return first, second


def test_whole_sample_file_is_idempotent(rules):
    first, second = redact_twice(rules, (ROOT / "input.ndjson").read_bytes())
    assert len(first) == 48
    assert second == first


@pytest.mark.parametrize("line", [
    '{"headers":{"X-Api-Key":"sk_live_abc123"}}',  # hash under a key rule (input line 1)
    '{"body":{"api_key":0}}',  # hash of a number
    '{"body":{"note":"mail a@b.com"}}',  # hash inside text
    '{"body":{"password":"hunter2","card_number":"4111111111111111","cvv":"1"}}',  # mask, partial, remove
    '{"body":"{\\"password\\": \\"x\\",  \\"n\\": 10.50}"}',  # JSON inside a string, re-encoded
    '{"body":"email=a%40b.com&password=x&api_key=k"}',  # form body
    '{"body":"login password=hunter2 api_key=abc"}',  # free text
    '{"path":"/r?token=abc&email=a%40b.com"}',  # query string
    '{"body":{"a":"\\ud800"}}',  # lone surrogate, escaped on output
])
def test_each_action_and_shape_is_stable(rules, line):
    first, second = redact_twice(rules, line + "\n")
    assert second == first


def test_already_masked_value_under_hash_rule_is_left_alone(redactor):
    # Input line 12 was redacted by someone before: X-Api-Key is "****". Hashing "****" would
    # pretend there was a real key; it stays "****" and isn't counted.
    assert redactor.redact_line('{"headers":{"X-Api-Key":"****"}}') == '{"headers":{"X-Api-Key":"****"}}'
    assert redactor.counts["api-key-names"] == 0


def test_error_records_pass_through_unchanged(rules):
    first, second = redact_twice(rules, "not json\n")
    assert first == second == ['{"redactor_error":{"line":1,"reason":"invalid JSON"}}']
