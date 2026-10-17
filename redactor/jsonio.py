"""JSON reading and writing that keeps what the standard library would change.

json.loads followed by json.dumps is not a faithful round trip:
- number literals are rewritten: 10.50 becomes 10.5 and 1e3 becomes 1000.0,
- a key that appears twice in one object keeps only its last value,
- NaN and Infinity are accepted, although they are not JSON.

A log redactor should change the secrets and nothing else, so this module keeps every
number as the text it had in the input, keeps repeated keys, and rejects NaN/Infinity.
"""

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Number:
    """A JSON number, kept as the exact text it had in the input (e.g. "10.50")."""

    text: str


class DuplicateKeyObject(list):
    """A JSON object that repeats a key, kept as a list of (key, value) pairs so nothing is lost.

    Objects without repeated keys stay plain dicts, so the common case costs nothing extra.
    """


def is_object(value) -> bool:
    return isinstance(value, (dict, DuplicateKeyObject))


def items(obj):
    """The (key, value) pairs of a JSON object, in input order."""
    return obj.items() if isinstance(obj, dict) else obj


def make_object(pairs: list) -> dict | DuplicateKeyObject:
    obj = dict(pairs)
    return obj if len(obj) == len(pairs) else DuplicateKeyObject(pairs)


def _reject_constant(name: str):
    raise ValueError(f"{name} is not valid JSON")


_decoder = json.JSONDecoder(
    object_pairs_hook=make_object,
    parse_int=Number,
    parse_float=Number,
    parse_constant=_reject_constant,
)


def loads(text: str):
    """Parse one JSON value. Raises ValueError for invalid JSON, RecursionError if absurdly deep."""
    return _decoder.decode(text)


def dumps(value) -> str:
    """Write a value as compact JSON on one line, numbers and repeated keys as they came in."""
    parts: list[str] = []
    _write(value, parts.append, False)
    text = "".join(parts)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate (from "\ud800" in the input) has no UTF-8 form, and writing it raw would
        # crash the output stream. Writing the line with \u escapes keeps it valid and identical in meaning.
        parts = []
        _write(value, parts.append, True)
        text = "".join(parts)
    return text


def _write(value, emit, ascii_only: bool) -> None:
    if isinstance(value, str):
        emit(json.dumps(value, ensure_ascii=ascii_only))
    elif isinstance(value, Number):
        emit(value.text)
    elif value is None:
        emit("null")
    elif value is True:
        emit("true")
    elif value is False:
        emit("false")
    elif isinstance(value, (int, float)):
        emit(json.dumps(value))  # numbers built in Python, e.g. in tests
    elif is_object(value):
        emit("{")
        for i, (key, item) in enumerate(items(value)):
            if i:
                emit(",")
            emit(json.dumps(key, ensure_ascii=ascii_only))
            emit(":")
            _write(item, emit, ascii_only)
        emit("}")
    elif isinstance(value, list):
        emit("[")
        for i, item in enumerate(value):
            if i:
                emit(",")
            _write(item, emit, ascii_only)
        emit("]")
    else:
        raise TypeError(f"cannot write {type(value).__name__} as JSON")
