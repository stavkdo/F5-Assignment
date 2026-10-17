"""The JSON layer (Phase 3d): what goes in comes out, except what the redactor changes on purpose."""

import pytest

from redactor import jsonio
from redactor.jsonio import DuplicateKeyObject, Number


@pytest.mark.parametrize("text", [
    '{"amount":10.50}',
    '{"exp":1e3}',
    '{"exp":1E+3}',
    '{"ratio":1.0}',
    '{"zero":-0}',
    '{"big":12345678901234567890}',
    '{"tiny":1.5e-300}',
    '[0.1,0.10,0.100]',
])
def test_numbers_round_trip_exactly(text):
    assert jsonio.dumps(jsonio.loads(text)) == text


def test_numbers_are_kept_as_text():
    assert jsonio.loads('{"a":10.50}') == {"a": Number("10.50")}


def test_duplicate_keys_are_kept_in_order():
    obj = jsonio.loads('{"email":"first","x":1,"email":"second"}')
    assert isinstance(obj, DuplicateKeyObject)
    assert list(jsonio.items(obj)) == [("email", "first"), ("x", Number("1")), ("email", "second")]
    assert jsonio.dumps(obj) == '{"email":"first","x":1,"email":"second"}'


def test_objects_without_duplicates_stay_plain_dicts():
    assert type(jsonio.loads('{"a":{"b":1}}')) is dict


@pytest.mark.parametrize("text", ["NaN", '{"a":Infinity}', '{"a":-Infinity}'])
def test_non_json_constants_are_rejected(text):
    with pytest.raises(ValueError):
        jsonio.loads(text)


def test_unicode_is_written_readably():
    assert jsonio.dumps({"city": "Zürich", "note": "名前 😀"}) == '{"city":"Zürich","note":"名前 😀"}'


def test_lone_surrogate_is_escaped_instead_of_crashing():
    # "\ud800" is valid JSON text but has no UTF-8 form; writing it raw would crash the output.
    out = jsonio.dumps(jsonio.loads('{"a":"\\ud800","b":"é"}'))
    out.encode("utf-8")  # must not raise
    assert out == '{"a":"\\ud800","b":"\\u00e9"}'
    assert jsonio.dumps(jsonio.loads(out)) == out  # stable on a second pass


def test_control_characters_stay_escaped():
    assert jsonio.dumps(jsonio.loads('"\\u0000PK\\u0003"')) == '"\\u0000PK\\u0003"'
