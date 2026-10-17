import copy

import pytest

from redactor.rules import RulesError, load_rules, parse_rules

VALID = {
    "settings": {"mask": {"replacement": "****"}, "partial": {"keep_last": 4, "fill": "*"}, "hash": {"algorithm": "sha256"}},
    "key_rules": [
        {"name": "auth", "scope": "headers", "match": {"exact": ["Authorization"]}, "action": "mask"},
        {"name": "secret", "scope": "body", "match": {"regex": "(?i)^password$"}, "action": "mask"},
    ],
    "value_rules": [
        {"name": "card", "pattern": r"\b\d{13,19}\b", "validator": "luhn", "action": "partial"},
    ],
}


def broken(change):
    data = copy.deepcopy(VALID)
    change(data)
    return data


def test_provided_rules_file_loads(rules):
    assert [r.name for r in rules.key_rules] == [
        "auth-headers", "api-key-names", "secret-fields", "card-number-fields", "cvv-fields",
    ]
    assert [r.name for r in rules.value_rules] == ["email", "jwt", "credit-card", "api-key-prefix"]
    assert rules.settings.mask == "****"
    assert rules.settings.keep_last == 4


def test_valid_config_parses():
    rules = parse_rules(VALID)
    assert rules.names() == ["auth", "secret", "card"]


def test_exact_match_is_case_insensitive():
    auth = parse_rules(VALID).key_rules[0]
    assert auth.matches("authorization", "headers")
    assert auth.matches("AUTHORIZATION", "headers")
    assert not auth.matches("Authorization", "body")  # wrong scope


@pytest.mark.parametrize("change, message", [
    (lambda d: d["key_rules"][0].update(action="explode"), "unknown action"),
    (lambda d: d["value_rules"][0].update(action=None), "unknown action"),
    (lambda d: d["value_rules"][0].update(pattern="(unclosed"), "invalid regex"),
    (lambda d: d["key_rules"][1]["match"].update(regex="[bad"), "invalid regex"),
    (lambda d: d["value_rules"][0].update(validator="mod97"), "unknown validator"),
    (lambda d: d["key_rules"][0].update(scope="cookies"), "unknown scope"),
    (lambda d: d["key_rules"][0]["match"].update(regex="x"), "exactly one"),
    (lambda d: d["key_rules"][0].update(match={}), "exactly one"),
    (lambda d: d["value_rules"][0].pop("pattern"), "missing 'pattern'"),
    (lambda d: d["key_rules"][1].update(name="auth"), "duplicate rule names"),
    (lambda d: d["settings"]["hash"].update(algorithm="md5"), "unsupported hash"),
])
def test_invalid_config_is_rejected(change, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(broken(change))


def test_non_mapping_is_rejected():
    with pytest.raises(RulesError):
        parse_rules(["not", "a", "mapping"])


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(RulesError, match="cannot read"):
        load_rules(str(tmp_path / "nope.yaml"))


def test_invalid_yaml_is_rejected(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("key_rules: [unclosed", encoding="utf-8")
    with pytest.raises(RulesError, match="invalid YAML"):
        load_rules(str(path))
