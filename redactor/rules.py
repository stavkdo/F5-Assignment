"""Load rules.yaml into compiled rule objects.

Every problem in the config (unknown action, bad regex, unknown validator, ...) raises
RulesError at load time, so the tool never starts with rules it doesn't understand.
"""

import re
from dataclasses import dataclass
from typing import Callable

import yaml

from redactor.actions import VALIDATORS

ACTIONS = {"mask", "partial", "hash", "remove"}
SCOPES = {"headers", "body", "any"}


class RulesError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    mask: str = "****"
    keep_last: int = 4
    fill: str = "*"


@dataclass(frozen=True)
class KeyRule:
    name: str
    scope: str
    action: str
    exact: frozenset[str]  # lower-cased names; empty when the rule uses a regex
    regex: re.Pattern | None

    def matches(self, key: str, scope: str | None) -> bool:
        # scope=None means "wherever": used for key=value pairs in free text, where we can't
        # tell whether the pair came from a header or a body field.
        if scope is not None and self.scope != "any" and self.scope != scope:
            return False
        if self.regex is not None:
            return self.regex.search(key) is not None
        return key.lower() in self.exact


@dataclass(frozen=True)
class ValueRule:
    name: str
    pattern: re.Pattern
    action: str
    validator: Callable[[str], bool] | None


@dataclass(frozen=True)
class Rules:
    settings: Settings
    key_rules: list[KeyRule]
    value_rules: list[ValueRule]

    def names(self) -> list[str]:
        return [r.name for r in self.key_rules] + [r.name for r in self.value_rules]


def load_rules(path: str) -> Rules:
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError as e:
        raise RulesError(f"cannot read rules file {path}: {e.strerror}") from e
    except yaml.YAMLError as e:
        raise RulesError(f"invalid YAML in {path}: {e}") from e
    return parse_rules(data)


TOP_LEVEL = {"version", "settings", "key_rules", "value_rules"}


def parse_rules(data) -> Rules:
    if not isinstance(data, dict):
        raise RulesError("rules file must be a YAML mapping")
    # A misspelled section ("key_rule:") would otherwise be ignored, and the tool would start
    # with fewer rules than intended: data it should redact would pass through.
    unknown = set(data) - TOP_LEVEL
    if unknown:
        raise RulesError(f"unknown top-level keys: {sorted(map(str, unknown))} (expected {sorted(TOP_LEVEL)})")

    rules = Rules(
        settings=_parse_settings(data.get("settings") or {}),
        key_rules=[_parse_key_rule(r) for r in _rule_list(data, "key_rules")],
        value_rules=[_parse_value_rule(r) for r in _rule_list(data, "value_rules")],
    )
    names = rules.names()
    if not names:
        # A file that parses but has no rules (an empty ConfigMap, the wrong file) would redact
        # nothing: the same as passing traffic through unredacted. Refuse it like a broken file.
        raise RulesError("the rules file has no rules: refusing to run without redaction")
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise RulesError(f"duplicate rule names: {sorted(duplicates)}")
    return rules


def _rule_list(data: dict, section: str) -> list[dict]:
    rules = data.get(section) or []
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        raise RulesError(f"{section} must be a list of rules (mappings)")
    return rules


def _parse_settings(raw: dict) -> Settings:
    algorithm = (raw.get("hash") or {}).get("algorithm", "sha256")
    if algorithm != "sha256":
        raise RulesError(f"unsupported hash algorithm: {algorithm!r} (only sha256)")
    partial = raw.get("partial") or {}
    settings = Settings(
        mask=(raw.get("mask") or {}).get("replacement", "****"),
        keep_last=partial.get("keep_last", 4),
        fill=partial.get("fill", "*"),
    )
    if not isinstance(settings.keep_last, int) or settings.keep_last < 0:
        raise RulesError("settings.partial.keep_last must be a non-negative integer")
    return settings


def _parse_key_rule(raw: dict) -> KeyRule:
    name = _require(raw, "name", "key rule")
    scope = raw.get("scope", "any")
    if scope not in SCOPES:
        raise RulesError(f"key rule {name!r}: unknown scope {scope!r}")
    action = _parse_action(raw, name)

    match = raw.get("match") or {}
    if ("exact" in match) == ("regex" in match):
        raise RulesError(f"key rule {name!r}: match needs exactly one of 'exact' or 'regex'")
    if "exact" in match:
        return KeyRule(name, scope, action, frozenset(n.lower() for n in match["exact"]), None)
    return KeyRule(name, scope, action, frozenset(), _compile(match["regex"], name))


def _parse_value_rule(raw: dict) -> ValueRule:
    name = _require(raw, "name", "value rule")
    action = _parse_action(raw, name)
    pattern = _compile(_require(raw, "pattern", f"value rule {name!r}"), name)

    validator = None
    if "validator" in raw:
        validator = VALIDATORS.get(raw["validator"])
        if validator is None:
            raise RulesError(f"value rule {name!r}: unknown validator {raw['validator']!r}")
    return ValueRule(name, pattern, action, validator)


def _parse_action(raw: dict, name: str) -> str:
    action = raw.get("action")
    if action not in ACTIONS:
        raise RulesError(f"rule {name!r}: unknown action {action!r}")
    return action


def _compile(pattern: str, name: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except re.error as e:
        raise RulesError(f"rule {name!r}: invalid regex: {e}") from e


def _require(raw: dict, field: str, what: str):
    if not isinstance(raw, dict) or field not in raw:
        raise RulesError(f"{what} is missing '{field}'")
    return raw[field]
