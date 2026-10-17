"""The redaction actions and validators, as small pure functions."""

import hashlib


def mask(value: str, replacement: str = "****") -> str:
    return replacement


def partial(value: str, keep_last: int = 4, fill: str = "*") -> str:
    # A value no longer than keep_last would be shown in full, so hide all of it.
    if len(value) <= keep_last:
        return fill * len(value)
    return fill * (len(value) - keep_last) + value[-keep_last:]


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def remove(value: str) -> str:
    # For value rules: delete the matched text. Key rules drop the whole key instead (see engine).
    return ""


def luhn(text: str) -> bool:
    """True if the digits in text pass the Luhn checksum. Spaces and dashes are ignored."""
    digits = [int(c) for c in text if c in "0123456789"]
    if not digits:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


VALIDATORS = {"luhn": luhn}
