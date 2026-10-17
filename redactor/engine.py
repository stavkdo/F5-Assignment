"""The redaction engine: one line of NDJSON in, one redacted line out.

The same Redactor serves the CLI and (later) the HTTP service.
"""

import re
from collections import Counter
from urllib.parse import quote_plus, unquote_plus

from redactor import actions, jsonio
from redactor.jsonio import Number, is_object, items, make_object
from redactor.rules import KeyRule, Rules, ValueRule

# The deepest nesting of arrays/objects we walk. Real traffic rarely goes past ~20 levels. The
# limit stops a hostile line from exhausting Python's call stack (1000 frames by default).
MAX_DEPTH = 100

# How many encodings we peel off one value. A JSON string inside a form field inside a JSON
# string is 3. Each level is another parse, so this bounds the work per line.
MAX_DECODES = 3

# The reasons a line can fail. A fixed vocabulary, so an error message can never carry line content.
INVALID_JSON = "invalid JSON"
NOT_AN_OBJECT = "not a JSON object"
TOO_DEEP = "nesting too deep"

# key=value or key: value inside free text, e.g. "login attempt password=hunter2". Keys and
# values are two patterns: a value is only read after a sensitive key, so a harmless key can't
# swallow a sensitive pair ("https://x/r?token=abc" is key "https", then key "token").
_TEXT_KEY = re.compile(r'(?<![\w.-])"?(?P<key>[A-Za-z_][\w.-]*)"?\s*[:=]\s*')
_TEXT_VALUE = re.compile(
    r"""
        "(?:[^"\\]|\\.)*"?                             # "double quoted", maybe cut off
      | '[^']*'?                                       # 'single quoted'
      | (?:(?i:bearer|basic|token)\s+)?[^\s,;&"'<>]+   # a bare word, with an optional auth scheme
    """,
    re.VERBOSE,
)

# application/x-www-form-urlencoded: name=value pairs joined by "&", no spaces.
_FORM_NAME = r"[\w.\-\[\]%+*]+"
_FORM = re.compile(rf"{_FORM_NAME}=[^&\s]*(?:&{_FORM_NAME}=[^&\s]*)*")
_URL_WITH_QUERY = re.compile(r"(?P<base>[^\s?]*)\?(?P<query>\S*)")


def _looks_like_json(text: str) -> bool:
    # A cheap first check before trying a full parse: an object, an array or a quoted string.
    return text.lstrip()[:1] in ("{", "[", '"')


class LineError(ValueError):
    """A line that can't be redacted. The message is one of the fixed reasons above."""


class Redactor:
    def __init__(self, rules: Rules):
        self.rules = rules
        self.counts: Counter[str] = Counter()  # rule name -> redactions, over all finished lines
        self._pending: Counter[str] = Counter()  # redactions in the line being processed

    def redact_line(self, line: str) -> str:
        try:
            record = jsonio.loads(line)
        except RecursionError:
            raise LineError(TOO_DEEP) from None
        except ValueError:
            raise LineError(INVALID_JSON) from None
        if not is_object(record):
            raise LineError(NOT_AN_OBJECT)
        return jsonio.dumps(self.redact_record(record))

    def redact_record(self, record):
        """Redact one parsed transaction. Its counts are kept only if the whole record succeeds."""
        self._pending = Counter()
        try:
            out = self._redact_message(record, 0, top=True)
        except RecursionError:  # the explicit depth limit should get there first; this is a backstop
            raise LineError(TOO_DEEP) from None
        self.counts.update(self._pending)
        return out

    def _redact_message(self, message, depth: int, top: bool):
        # A message is the transaction itself or its "response". "headers" is walked with the
        # headers scope. Every other field, ts and path included, is walked as body data, so a
        # field we don't know about is redacted instead of passed through (default deny).
        pairs = []
        for key, value in items(message):
            if key == "headers":
                pairs.append((key, self._walk(value, "headers", depth + 1, 0)))
            elif key == "response" and top and is_object(value):
                pairs.append((key, self._redact_message(value, depth + 1, top=False)))
            else:
                pair = self._redact_pair(key, value, "body", depth + 1, 0)
                if pair is not None:
                    pairs.append(pair)
        return make_object(pairs)

    def _walk(self, value, scope: str, depth: int, decodes: int):
        if depth > MAX_DEPTH:
            raise LineError(TOO_DEEP)
        if is_object(value):
            pairs = [self._redact_pair(k, v, scope, depth + 1, decodes) for k, v in items(value)]
            return make_object([p for p in pairs if p is not None])
        if isinstance(value, list):
            return [self._walk(item, scope, depth + 1, decodes) for item in value]
        if isinstance(value, str):
            return self._redact_string(value, depth, decodes)
        if isinstance(value, Number) and value.text.isdigit():
            return self._redact_integer(value)
        return value  # booleans, null, and numbers with a sign, fraction or exponent

    def _redact_integer(self, number: Number):
        # A card stored as a JSON number ("amount": 4111111111111111) is still a card, so an
        # integer's digits go through the value rules too. Only a number that gets redacted
        # changes type, to a string. Every other number keeps its type and exact text.
        out = self._apply_value_rules(number.text)
        return number if out == number.text else out

    def _redact_pair(self, key: str, value, scope: str, depth: int, decodes: int):
        """One key and its value. Returns None when a remove rule drops the key."""
        rule = self._key_rule_for(key, scope)
        key_out = self._apply_value_rules(key)  # an email used as a key is still an email
        if rule is None:
            return key_out, self._walk(value, scope, depth, decodes)
        if rule.action == "remove":
            self._count(rule)
            return None
        return key_out, self._apply_key_rule(rule, value, depth)

    def _key_rule_for(self, key: str, scope: str | None) -> KeyRule | None:
        #draws the right rule for the key 
        for rule in self.rules.key_rules:
            if rule.matches(key, scope):
                return rule
        return None

    def _apply_key_rule(self, rule: KeyRule, value, depth: int):
        # The action applies to every scalar under the key, and containers keep their shape:
        # ["a", "b"] under Set-Cookie becomes ["****", "****"] and is still a list.
        if depth > MAX_DEPTH:
            raise LineError(TOO_DEEP)
        if value is None or isinstance(value, bool):
            return value  # null/true/false hold no secret, so they are kept and keep their type
        if is_object(value):
            return make_object([(k, self._apply_key_rule(rule, v, depth + 1)) for k, v in items(value)])
        if isinstance(value, list):
            return [self._apply_key_rule(rule, item, depth + 1) for item in value]
        text = value if isinstance(value, str) else jsonio.dumps(value)  # a number becomes a string
        if rule.action == "hash" and self._already_redacted(text):
            return text
        self._count(rule)
        return self._apply_action(rule.action, text)

    def _already_redacted(self, text: str) -> bool:
        # hash is the one action that isn't idempotent: hash(hash(x)) != hash(x). So it recognises
        # its own output, or a mask left by an earlier run, and leaves them alone.
        return text == self.rules.settings.mask or actions.is_hash(text)

    def _redact_string(self, text: str, depth: int = 0, decodes: int = 0) -> str:
        # Peel off an encoding if the text has one, otherwise treat it as free text. Anything we
        # decode is payload, so its keys are matched with the body scope, even inside a header.
        if _looks_like_json(text):
            out = self._redact_embedded_json(text, depth, decodes)
            if out is not None:
                return out
        if decodes < MAX_DECODES:
            url = _URL_WITH_QUERY.fullmatch(text)
            if url and _FORM.fullmatch(url["query"]):
                return self._redact_text(url["base"]) + "?" + self._redact_form(url["query"], depth, decodes)
            if _FORM.fullmatch(text):
                return self._redact_form(text, depth, decodes)
        return self._redact_text(text)

    def _redact_embedded_json(self, text: str, depth: int, decodes: int) -> str | None:
        """A string that holds JSON, like the /v1/legacy body. None if it isn't valid JSON.

        That JSON may itself be a string (double-encoded JSON, common in logs), which is
        one more level to decode.
        """
        try:
            parsed = jsonio.loads(text)
        except RecursionError:
            raise LineError(TOO_DEEP) from None
        except ValueError:
            return None  # not JSON after all, or cut off: the caller treats it as free text
        if decodes >= MAX_DECODES:
            if isinstance(parsed, str) and not _looks_like_json(parsed):
                return None  # just a quoted word: plain text
            # More JSON than we are willing to unpack. Its quotes are escaped, so the free-text
            # scan can't read it either. Fail closed: refuse the line rather than pass it unread.
            raise LineError(TOO_DEEP)
        before = sum(self._pending.values())
        redacted = self._walk(parsed, "body", depth + 1, decodes + 1)
        if sum(self._pending.values()) == before:
            return text  # nothing to redact: keep the original exactly, spacing included
        return jsonio.dumps(redacted)

    def _redact_form(self, text: str, depth: int, decodes: int) -> str:
        # Decode each name and value, redact, and re-encode only the pairs that changed, so the
        # untouched pairs keep their exact original encoding.
        out = []
        for pair in text.split("&"):
            raw_name, _, raw_value = pair.partition("=")
            name, value = unquote_plus(raw_name), unquote_plus(raw_value)
            rule = self._key_rule_for(name, "body")
            if rule is not None and rule.action == "remove":
                self._count(rule)
                continue
            if rule is not None:
                new = self._apply_key_rule(rule, value, depth)
            else:
                new = self._redact_string(value, depth, decodes + 1)
            out.append(pair if new == value else f"{raw_name}={quote_plus(new, safe='*:')}")
        return "&".join(out)

    def _redact_text(self, text: str) -> str:
        """Free text: first key=value pairs with a sensitive key name, then the value rules."""
        if "=" in text or ":" in text:
            text = self._redact_text_pairs(text)
        return self._apply_value_rules(text)

    def _redact_text_pairs(self, text: str) -> str:
        # In free text we can't tell a header from a body field, so every key rule applies,
        # whatever its scope. Over-redacting a log line is cheaper than leaking a password.
        # One left-to-right pass: O(n), whatever the text looks like.
        out, pos = [], 0
        for key in _TEXT_KEY.finditer(text):
            if key.start() < pos:
                continue  # inside a value we already redacted
            rule = self._key_rule_for(key["key"], None)
            if rule is None:
                continue
            value = _TEXT_VALUE.match(text, key.end())
            if value is None:
                continue  # "password=" with nothing after it
            out.append(text[pos:key.start()])
            if rule.action == "remove":
                self._count(rule)
            else:
                out.append(key[0] + self._redact_text_value(rule, value[0]))
            pos = value.end()
        out.append(text[pos:])
        return "".join(out)

    def _redact_text_value(self, rule: KeyRule, value: str) -> str:
        # Keep the quotes around a quoted value, redact what's between them.
        quote = value[0] if value[0] in "\"'" else ""
        inner = value[len(quote):]
        closing = quote if quote and inner.endswith(quote) else ""
        if closing:
            inner = inner[:-1]
        return quote + self._apply_key_rule(rule, inner, 0) + closing

    def _apply_value_rules(self, text: str) -> str:
        # Value rules run in config order; each one sees the previous one's output.
        for rule in self.rules.value_rules:
            text = rule.pattern.sub(lambda m, rule=rule: self._replace_match(rule, m.group(0)), text)
        return text

    def _replace_match(self, rule: ValueRule, found: str) -> str:
        if rule.validator is not None and not rule.validator(found):
            return found
        self._count(rule)
        return self._apply_action(rule.action, found)

    def _count(self, rule: KeyRule | ValueRule) -> None:
        self._pending[rule.name] += 1

    def _apply_action(self, action: str, value: str) -> str:
        settings = self.rules.settings
        if action == "mask":
            return actions.mask(value, settings.mask)
        if action == "partial":
            return actions.partial(value, settings.keep_last, settings.fill)
        if action == "hash":
            if settings.hmac_key is not None:
                return actions.hmac_sha256(value, settings.hmac_key)
            return actions.sha256(value)
        return actions.remove(value)
