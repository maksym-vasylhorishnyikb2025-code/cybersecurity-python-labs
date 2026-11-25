"""Shared pytest fixtures and network isolation for Lab 04."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent real HTTP calls and clear inherited NVD_API_KEY."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    """Return a fresh copy of the synthetic NVD sample payload."""
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    return copy.deepcopy(data)
