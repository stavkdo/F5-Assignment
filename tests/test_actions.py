import pytest

from redactor.actions import luhn, mask, partial, remove, sha256


def test_mask_replaces_whole_value():
    assert mask("hunter2") == "****"
    assert mask("hunter2", "[X]") == "[X]"


def test_partial_keeps_last_four():
    assert partial("4111111111111111") == "************1111"


def test_partial_custom_settings():
    assert partial("abcdef", keep_last=2, fill="#") == "####ef"


@pytest.mark.parametrize("value", ["1234", "123", ""])
def test_partial_hides_short_values_completely(value):
    assert partial(value) == "*" * len(value)


def test_sha256_known_digest():
    assert sha256("a@b.com") == "fb98d44ad7501a959f3f4f4a3f004fe2d9e581ea6207e218c4b02c08a4d75adf"


def test_remove_returns_empty_string():
    assert remove("anything") == ""


@pytest.mark.parametrize("number", [
    "4111111111111111",     # Visa test card
    "5555555555554444",     # Mastercard
    "378282246310005",      # Amex
    "4111 1111 1111 1111",  # separators are ignored
    "5555-5555-5555-4444",
])
def test_luhn_accepts_valid_numbers(number):
    assert luhn(number)


@pytest.mark.parametrize("number", [
    "4111111111111112",  # order reference on input line 4
    "1705312800123456",  # microsecond timestamp on input line 35
    "",
    "abc",
])
def test_luhn_rejects_invalid_numbers(number):
    assert not luhn(number)
