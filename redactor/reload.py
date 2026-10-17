"""Hot reload of the rules file for long-running CLI streams (redactor --watch-rules).

    tail -f app.log | redactor --watch-rules > redacted.log

Between two lines, at most every CHECK_INTERVAL seconds, the rules file is read again. If its
content changed and the new rules are valid, they replace the old ones before the next line.
If they are invalid, or the file can't be read, the old rules stay: the stream never runs with
no rules or half-understood rules, the same "fail closed" as at startup.
"""

import hashlib
import time
from typing import Callable, TextIO

from redactor.engine import Redactor
from redactor.rules import Rules, RulesError, parse_rules_file

CHECK_INTERVAL = 2.0  # seconds; reading a small file this often costs nothing measurable


class RulesWatcher:
    def __init__(
        self,
        path: str,
        loaded_from: bytes,
        redactor: Redactor,
        err: TextIO,
        prepare: Callable[[Rules], Rules] = lambda rules: rules,
        interval: float = CHECK_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.path = path
        self.redactor = redactor
        self.err = err
        self.prepare = prepare  # applied to every new rule set, e.g. to add the --hmac key
        self.interval = interval
        self.clock = clock
        self.reloads = 0
        self._last_check = clock()
        # The bytes the current rules came from, not a fresh read: a change made right after
        # startup would otherwise look like "no change".
        self._seen = hashlib.sha256(loaded_from).digest()
        self._unreadable = False

    def check(self) -> None:
        """Called before each line. Cheap unless the interval has passed and the file changed."""
        now = self.clock()
        if now - self._last_check < self.interval:
            return
        self._last_check = now
        try:
            with open(self.path, "rb") as f:
                content = f.read()
        except OSError as e:
            if not self._unreadable:  # say it once, not every 2 seconds
                self._unreadable = True
                self.err.write(f"redactor: rules not reloaded: cannot read {self.path}: {e.strerror}; keeping the current rules\n")
            return
        self._unreadable = False
        fingerprint = hashlib.sha256(content).digest()
        if fingerprint == self._seen:
            return
        # Remember this content even if it's invalid, so the same broken file is reported once.
        self._seen = fingerprint
        try:
            rules = self.prepare(parse_rules_file(content, self.path))
        except RulesError as e:
            self.err.write(f"redactor: rules not reloaded: {e}; keeping the current rules\n")
            return
        # Swapped between two lines, so every line is redacted entirely by one rule set.
        self.redactor.rules = rules
        self.reloads += 1
        self.err.write(f"redactor: rules reloaded from {self.path} ({len(rules.names())} rules)\n")
