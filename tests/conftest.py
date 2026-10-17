import io
from pathlib import Path

import pytest

from redactor.engine import Redactor
from redactor.rules import load_rules
from redactor.stream import redact_stream

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rules():
    return load_rules(str(ROOT / "rules.yaml"))


@pytest.fixture
def redactor(rules):
    return Redactor(rules)


def run_stream(redactor, data, **kwargs):
    """Feed str or bytes through redact_stream. Returns (stdout lines, stderr text, stats)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    out, err = io.StringIO(), io.StringIO()
    stats = redact_stream(redactor, io.BytesIO(data), out, err, **kwargs)
    return out.getvalue().splitlines(), err.getvalue(), stats


def redact_body(redactor, body) -> str:
    """Redact a line whose body is `body` (any JSON value) and return the output line."""
    import json

    return redactor.redact_line(json.dumps({"body": body}))
