"""Bonus: --watch-rules reloads the rules file during a CLI stream, only if the new rules are valid."""

import io
import queue
import subprocess
import sys
import threading
import time

import pytest

from conftest import ROOT, run_stream
from redactor.cli import main
from redactor.engine import Redactor
from redactor.reload import CHECK_INTERVAL, RulesWatcher
from redactor.rules import read_rules_file, with_hmac_key
from redactor.stream import format_summary

RULES_A = """version: 1
key_rules:
  - name: secret-fields
    match: {exact: [password]}
    action: mask
"""
RULES_B = RULES_A + """  - name: pin-fields
    match: {exact: [pin]}
    action: mask
"""
LINE = '{"body":{"password":"hunter2","pin":"1234"}}'


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@pytest.fixture
def setup(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(RULES_A, encoding="utf-8")
    rules, content = read_rules_file(str(path))
    redactor = Redactor(rules)
    err = io.StringIO()
    clock = Clock()
    watcher = RulesWatcher(str(path), content, redactor, err, clock=clock)
    return path, redactor, watcher, err, clock


def test_valid_new_rules_are_used_from_the_next_line(setup):
    path, redactor, watcher, err, clock = setup
    assert redactor.redact_line(LINE) == '{"body":{"password":"****","pin":"1234"}}'
    path.write_text(RULES_B, encoding="utf-8")
    clock.now += CHECK_INTERVAL
    watcher.check()
    assert redactor.redact_line(LINE) == '{"body":{"password":"****","pin":"****"}}'
    assert watcher.reloads == 1
    assert "rules reloaded" in err.getvalue()


def test_the_file_is_not_read_again_before_the_interval(setup):
    path, redactor, watcher, err, clock = setup
    path.write_text(RULES_B, encoding="utf-8")
    clock.now += CHECK_INTERVAL / 2
    watcher.check()
    assert watcher.reloads == 0


def test_an_unchanged_file_is_not_reloaded(setup):
    _, _, watcher, err, clock = setup
    clock.now += CHECK_INTERVAL
    watcher.check()
    assert (watcher.reloads, err.getvalue()) == (0, "")


@pytest.mark.parametrize("broken", [
    "key_rules: [",  # invalid YAML
    "",  # empty: would redact nothing
    "version: 1\n",  # no rules
    RULES_A.replace("mask", "scramble"),  # unknown action
])
def test_invalid_new_rules_keep_the_old_ones(setup, broken):
    path, redactor, watcher, err, clock = setup
    path.write_text(broken, encoding="utf-8")
    clock.now += CHECK_INTERVAL
    watcher.check()
    assert redactor.redact_line(LINE) == '{"body":{"password":"****","pin":"1234"}}'  # still redacting
    assert "rules not reloaded" in err.getvalue()
    assert "keeping the current rules" in err.getvalue()


def test_a_broken_file_is_reported_once_and_a_fix_is_picked_up(setup):
    path, redactor, watcher, err, clock = setup
    path.write_text("key_rules: [", encoding="utf-8")
    for _ in range(3):
        clock.now += CHECK_INTERVAL
        watcher.check()
    assert err.getvalue().count("rules not reloaded") == 1
    path.write_text(RULES_B, encoding="utf-8")
    clock.now += CHECK_INTERVAL
    watcher.check()
    assert watcher.reloads == 1


def test_a_deleted_file_keeps_the_old_rules_and_is_reported_once(setup):
    path, redactor, watcher, err, clock = setup
    path.unlink()
    for _ in range(3):
        clock.now += CHECK_INTERVAL
        watcher.check()
    assert err.getvalue().count("cannot read") == 1
    assert redactor.redact_line(LINE) == '{"body":{"password":"****","pin":"1234"}}'


def test_the_hmac_key_survives_a_reload(tmp_path):
    key = b"0123456789abcdef0123456789abcdef"
    path = tmp_path / "rules.yaml"
    path.write_text(RULES_A.replace("password]", "email]").replace("mask", "hash"), encoding="utf-8")
    rules, content = read_rules_file(str(path))
    redactor = Redactor(with_hmac_key(rules, key))
    clock = Clock()
    watcher = RulesWatcher(str(path), content, redactor, io.StringIO(),
                           prepare=lambda r: with_hmac_key(r, key), clock=clock)
    path.write_text(path.read_text(encoding="utf-8").replace("secret-fields", "email-fields"), encoding="utf-8")
    clock.now += CHECK_INTERVAL
    watcher.check()
    assert watcher.reloads == 1
    assert '"hmac-sha256:' in redactor.redact_line('{"body":{"email":"bob@example.com"}}')


def test_rules_change_between_lines_of_a_stream_and_counts_survive(setup):
    path, redactor, watcher, err, clock = setup

    def before_line():
        # Pretend the file was edited, and the interval passed, right after the first line.
        if redactor.counts["secret-fields"] == 1:
            path.write_text(RULES_B.replace("secret-fields", "renamed"), encoding="utf-8")
            clock.now += CHECK_INTERVAL
        watcher.check()

    out, _, stats = run_stream(redactor, f"{LINE}\n{LINE}\n", before_line=before_line)
    assert out == ['{"body":{"password":"****","pin":"1234"}}', '{"body":{"password":"****","pin":"****"}}']
    assert dict(redactor.counts) == {"secret-fields": 1, "renamed": 1, "pin-fields": 1}
    # secret-fields was removed by the reload, but its redaction happened, so it's still listed.
    assert "secret-fields" in format_summary(redactor, stats)


def test_watch_rules_is_cli_only():
    with pytest.raises(SystemExit) as e:
        main(["--serve", "--watch-rules"])
    assert e.value.code == 2


def test_cli_picks_up_a_rules_change_in_a_live_stream(tmp_path):
    """The real command, fed line by line like `tail -f app.log | redactor --watch-rules`."""
    path = tmp_path / "rules.yaml"
    path.write_text(RULES_A, encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "redactor", "--rules", str(path), "--watch-rules"],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    lines: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout], daemon=True).start()
    try:
        proc.stdin.write(LINE.encode() + b"\n")
        proc.stdin.flush()
        # Each output line is flushed as soon as it's written, so it arrives while stdin is open.
        assert lines.get(timeout=10) == b'{"body":{"password":"****","pin":"1234"}}\n'
        path.write_text(RULES_B, encoding="utf-8")
        time.sleep(CHECK_INTERVAL + 0.3)
        proc.stdin.write(LINE.encode() + b"\n")
        proc.stdin.flush()
        assert lines.get(timeout=10) == b'{"body":{"password":"****","pin":"****"}}\n'
    finally:
        proc.stdin.close()
        err = proc.stderr.read().decode()
        proc.wait(timeout=10)
    assert "rules reloaded" in err
    assert proc.returncode == 0
