"""Load rules.yaml into compiled rule objects.

Every problem in the config (unknown action, bad regex, unknown validator, ...) raises
RulesError at load time, so the tool never starts with rules it doesn't understand.
"""

import dataclasses
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Mapping

import yaml

from redactor.actions import VALIDATORS

ACTIONS = {"mask", "partial", "hash", "remove"}
SCOPES = {"headers", "body", "any"}

# --hmac reads its key from the environment, never from rules.yaml (which is in git and in a
# ConfigMap anyone in the namespace can read) or from the command line (shell history, ps).
HMAC_KEY_ENV = "REDACTOR_HMAC_KEY"
MIN_HMAC_KEY_BYTES = 32  # as long as the SHA-256 output (RFC 2104 advises at least that)


class RulesError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    mask: str = "****"
    keep_last: int = 4
    fill: str = "*"
    # Set by --hmac. repr=False so the key can't end up in a log or a traceback.
    hmac_key: bytes | None = field(default=None, repr=False)


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
    return read_rules_file(path)[0]


def read_rules_file(path: str) -> tuple[Rules, bytes]:
    """The rules, and the exact bytes they came from (the watcher compares later reads to them)."""
    try:
        with open(path, "rb") as f:
            content = f.read()
    except OSError as e:
        raise RulesError(f"cannot read rules file {path}: {e.strerror}") from e
    return parse_rules_file(content, path), content


def parse_rules_file(content: bytes, path: str) -> Rules:
    """Rules from the bytes of a rules file. Used at startup and by the rules watcher."""
    try:
        data = yaml.safe_load(content.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise RulesError(f"rules file {path} is not UTF-8") from e
    except yaml.YAMLError as e:
        raise RulesError(f"invalid YAML in {path}: {e}") from e
    return parse_rules(data)


def hmac_key_from_env(environ: Mapping[str, str] = os.environ) -> bytes:
    """The --hmac key. Missing or short means refuse to run, never fall back to plain SHA-256."""
    key = environ.get(HMAC_KEY_ENV, "").encode("utf-8")
    if len(key) < MIN_HMAC_KEY_BYTES:
        # The message says what's wrong, never what the key is.
        state = "is not set" if not key else "is too short"
        raise RulesError(f"--hmac needs a secret key of at least {MIN_HMAC_KEY_BYTES} bytes in {HMAC_KEY_ENV}, and it {state}")
    return key


def with_hmac_key(rules: Rules, key: bytes) -> Rules:
    """The same rules, with the hash action switched to HMAC-SHA256 under this key."""
    return dataclasses.replace(rules, settings=dataclasses.replace(rules.settings, hmac_key=key))


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
