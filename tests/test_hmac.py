"""Bonus: --hmac hashes with HMAC-SHA256 under a secret key from REDACTOR_HMAC_KEY."""

import hashlib
import hmac
import os
import re
import subprocess
import sys

import pytest

from conftest import ROOT, run_stream
from redactor.actions import hmac_sha256, is_hash, sha256
from redactor.cli import main
from redactor.engine import Redactor
from redactor.rules import HMAC_KEY_ENV, RulesError, hmac_key_from_env, with_hmac_key

KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes, test only
SAMPLE = (ROOT / "input.ndjson").read_bytes()
PLAIN_SHA256 = re.compile(r"(?<!hmac-)sha256:[0-9a-f]{64}")


def test_hmac_sha256_is_the_standard_hmac():
    expected = hmac.new(KEY, b"bob@example.com", hashlib.sha256).hexdigest()
    assert hmac_sha256("bob@example.com", KEY) == "hmac-sha256:" + expected


def test_same_value_same_output_but_the_key_changes_it():
    # Equal inputs still correlate ("same user"), but a different key gives unrelated outputs,
    # and neither is the plain SHA-256 an attacker could compute from a guess.
    a = hmac_sha256("bob@example.com", KEY)
    assert a == hmac_sha256("bob@example.com", KEY)
    assert a != hmac_sha256("bob@example.com", b"another key of at least 32 bytes!")
    assert a.removeprefix("hmac-sha256:") != sha256("bob@example.com").removeprefix("sha256:")


def test_both_hash_formats_are_recognised():
    assert is_hash(hmac_sha256("x", KEY))
    assert is_hash(sha256("x"))
    assert not is_hash("hmac-sha256:" + "0" * 63)


@pytest.fixture
def hmac_redactor(rules):
    return Redactor(with_hmac_key(rules, KEY))


def test_sample_file_with_hmac_has_no_plain_sha256(hmac_redactor):
    out, _, stats = run_stream(hmac_redactor, SAMPLE)
    text = "\n".join(out)
    assert stats.redacted == 43
    assert text.count("hmac-sha256:") == hmac_redactor.counts["email"] + hmac_redactor.counts["api-key-names"]
    assert not PLAIN_SHA256.search(text)


def test_hmac_output_is_idempotent(hmac_redactor, rules):
    once, _, _ = run_stream(hmac_redactor, SAMPLE)
    twice, _, _ = run_stream(Redactor(with_hmac_key(rules, KEY)), "\n".join(once))
    assert twice == once


def test_old_sha256_values_are_left_alone_in_hmac_mode(hmac_redactor):
    # Logs redacted before --hmac was turned on: a stored hash is not hashed again.
    old = sha256("bob@example.com")
    assert hmac_redactor.redact_line(f'{{"body":{{"email":"{old}"}}}}') == f'{{"body":{{"email":"{old}"}}}}'


@pytest.mark.parametrize("environ, state", [({}, "is not set"), ({HMAC_KEY_ENV: "tiny-secret"}, "is too short")])
def test_missing_or_short_key_is_refused(environ, state):
    with pytest.raises(RulesError, match=state) as e:
        hmac_key_from_env(environ)
    assert "tiny-secret" not in str(e.value)  # says what's wrong, never what the key is


def test_a_32_byte_key_is_accepted():
    assert hmac_key_from_env({HMAC_KEY_ENV: KEY.decode()}) == KEY


def test_the_key_never_appears_in_repr(rules):
    assert KEY.decode() not in repr(with_hmac_key(rules, KEY))


def run_cli(*args, key=None):
    env = {k: v for k, v in os.environ.items() if k != HMAC_KEY_ENV}
    if key is not None:
        env[HMAC_KEY_ENV] = key
    return subprocess.run([sys.executable, "-m", "redactor", *args], cwd=ROOT, env=env,
                          capture_output=True, encoding="utf-8")


def test_cli_without_a_key_refuses_to_run():
    result = run_cli("--hmac", "input.ndjson")
    assert result.returncode == 2
    assert result.stdout == ""
    assert HMAC_KEY_ENV in result.stderr


def test_cli_with_a_short_key_refuses_and_does_not_print_it():
    result = run_cli("--hmac", "input.ndjson", key="not-long-enough-xyz")
    assert result.returncode == 2
    assert "not-long-enough-xyz" not in result.stderr


def test_cli_with_a_key():
    result = run_cli("--hmac", "input.ndjson", key=KEY.decode())
    assert result.returncode == 0
    assert "hmac-sha256:" in result.stdout
    assert not PLAIN_SHA256.search(result.stdout)
    assert KEY.decode() not in result.stdout + result.stderr


def test_a_key_in_the_environment_alone_changes_nothing():
    # HMAC is switched on by the flag, never by a variable that happens to be set.
    result = run_cli("input.ndjson", key=KEY.decode())
    assert result.returncode == 0
    assert "hmac-sha256:" not in result.stdout
    assert PLAIN_SHA256.search(result.stdout)


def test_serve_with_hmac_but_no_key_never_opens_the_port(monkeypatch, capsys):
    monkeypatch.delenv(HMAC_KEY_ENV, raising=False)
    assert main(["--serve", "--hmac", "--rules", str(ROOT / "rules.yaml")]) == 2
    assert HMAC_KEY_ENV in capsys.readouterr().err
