from pathlib import Path

import pytest

from redactor.engine import Redactor
from redactor.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rules():
    return load_rules(str(ROOT / "rules.yaml"))


@pytest.fixture
def redactor(rules):
    return Redactor(rules)
