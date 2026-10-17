"""The redaction engine: one line of NDJSON in, one redacted line out.

The same Redactor serves the CLI and (later) the HTTP service.
"""

import json
from collections import Counter

from redactor import actions
from redactor.rules import KeyRule, Rules, ValueRule


class LineError(ValueError):
    """A line that can't be redacted. The message must never contain line content."""


class Redactor:
    def __init__(self, rules: Rules):
        self.rules = rules
        self.counts: Counter[str] = Counter()  # rule name -> number of redactions

    def redact_line(self, line: str) -> str:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            raise LineError("invalid JSON") from None
        if not isinstance(record, dict):
            raise LineError("not a JSON object")
        redacted = self.redact_record(record)
        return json.dumps(redacted, ensure_ascii=False, separators=(",", ":"))

    def redact_record(self, record: dict) -> dict:
        out = self._redact_message(record)
        if isinstance(out.get("response"), dict):
            out["response"] = self._redact_message(out["response"])
        return out

    def _redact_message(self, message: dict) -> dict:
        # The field name doubles as the key-rule scope: "headers" or "body".
        # Other fields (ts, method, path, status) are passed through unchanged.
        out = dict(message)
        for field in ("headers", "body"):
            if field in out:
                out[field] = self._walk(out[field], field)
        return out

    def _walk(self, value, scope: str):
        if isinstance(value, dict):
            return self._walk_dict(value, scope)
        if isinstance(value, list):
            return [self._walk(item, scope) for item in value]
        if isinstance(value, str):
            return self._redact_string(value)
        return value  # numbers, booleans, null

    def _walk_dict(self, obj: dict, scope: str) -> dict:
        out = {}
        for key, value in obj.items():
            rule = self._key_rule_for(key, scope)
            if rule is None:
                out[key] = self._walk(value, scope)
            elif rule.action == "remove":
                self.counts[rule.name] += 1
            else:
                out[key] = self._apply_key_rule(rule, value)
        return out

    def _key_rule_for(self, key: str, scope: str) -> KeyRule | None:
        #draws the right rule for the key 
        for rule in self.rules.key_rules:
            if rule.matches(key, scope):
                return rule
        return None

    def _apply_key_rule(self, rule: KeyRule, value):
        # TODO (phase 3b): decide properly what to do with non-string values.
        # For now: null and booleans carry no secret and are kept; anything else
        # (numbers, lists, objects) is redacted as its JSON text.
        if value is None or isinstance(value, bool):
            return value
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        self.counts[rule.name] += 1
        return self._apply_action(rule.action, text)

    def _redact_string(self, text: str) -> str:
        # Value rules run in config order; each one sees the previous one's output.
        for rule in self.rules.value_rules:
            text = rule.pattern.sub(lambda m, rule=rule: self._replace_match(rule, m.group(0)), text)
        return text

    def _replace_match(self, rule: ValueRule, found: str) -> str:
        if rule.validator is not None and not rule.validator(found):
            return found
        self.counts[rule.name] += 1
        return self._apply_action(rule.action, found)

    def _apply_action(self, action: str, value: str) -> str:
        settings = self.rules.settings
        if action == "mask":
            return actions.mask(value, settings.mask)
        if action == "partial":
            return actions.partial(value, settings.keep_last, settings.fill)
        if action == "hash":
            return actions.sha256(value)
        return actions.remove(value)
