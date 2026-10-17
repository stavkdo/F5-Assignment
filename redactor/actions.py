"""The redaction actions and validators, as small pure functions."""

import hashlib
import hmac
import re

HASH_PREFIX = "sha256:"
HMAC_PREFIX = "hmac-sha256:"
_HASH_TOKEN = re.compile(r"(?:sha256|hmac-sha256):[0-9a-f]{64}")


def mask(value: str, replacement: str = "****") -> str:
    return replacement


def partial(value: str, keep_last: int = 4, fill: str = "*") -> str:
    # A value no longer than keep_last would be shown in full, so hide all of it.
    if len(value) <= keep_last:
        return fill * len(value)
    return fill * (len(value) - keep_last) + value[-keep_last:]


def sha256(value: str) -> str:
    # The "sha256:" prefix makes the output recognisable, so a second run can leave it alone
    # instead of hashing the hash (see is_hash and the engine's idempotency check).
    return HASH_PREFIX + hashlib.sha256(value.encode("utf-8")).hexdigest()


def hmac_sha256(value: str, key: bytes) -> str:
    # Plain SHA-256 of a card or an email can be guessed forwards: hash every candidate and
    # compare. HMAC mixes a secret key into the hash, so without the key nobody can test a guess.
    # Equal values still give equal outputs, so "same user" can still be seen across lines.
    return HMAC_PREFIX + hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def is_hash(text: str) -> bool:
    """True if text is exactly what sha256() or hmac_sha256() produces."""
    return _HASH_TOKEN.fullmatch(text) is not None


def remove(value: str) -> str:
    # For value rules: delete the matched text. Key rules drop the whole key instead (see engine).
    return ""


def luhn(text: str) -> bool:
    """True if the digits in text pass the Luhn checksum. Spaces and dashes are ignored."""
    # isdecimal() accepts every Unicode digit (full-width, Arabic-Indic, ...), the same set the
    # regex \d matches, and int() converts any of them: int("４") == 4.
    digits = [int(c) for c in text if c.isdecimal()]
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
