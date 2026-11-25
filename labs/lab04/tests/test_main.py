"""Integration and CLI tests for labs.lab04.main."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


def test_cli_local_input_success(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Local --input mode outputs valid JSON report and makes no HTTP calls."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", 4)
    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(SAMPLE_PATH)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    data = json.loads(captured.out)
    assert data["cve_id"] == "CVE-2099-10001"
    assert data["variant"] == 4
    assert data["decision"] == "review"


def test_cli_invalid_json_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed JSON file returns exit code 1 and prints error to stderr."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", 4)
    bad_file = tmp_path / "broken.json"
    bad_file.write_text("{invalid json", encoding="utf-8")

    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(bad_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "not valid JSON" in captured.err


def test_cli_missing_input_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing local file returns exit code 1 and prints error to stderr."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", 4)
    missing = tmp_path / "does_not_exist.json"

    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(missing)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "failed to read" in captured.err


@pytest.mark.parametrize("bad_cve", ["cve-2021-44228", "CVE-21-44228", "CVE-2021-123"])
def test_cli_invalid_cve(bad_cve: str, capsys: pytest.CaptureFixture[str]) -> None:
    """Invalid --cve identifier exits with code 2 and stderr message."""
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", bad_cve, "--input", str(SAMPLE_PATH)])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert captured.out == ""
    assert captured.err != ""


@pytest.mark.parametrize("bad_variant", [0, 16, True, "4"])
def test_cli_invalid_variant_number(
    bad_variant: object,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid VARIANT_NUMBER returns exit code 2 and stderr message."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", bad_variant)
    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(SAMPLE_PATH)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "VARIANT_NUMBER" in captured.err


def test_cli_network_http_error_hides_secret(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """HTTP error in network mode returns code 1 and never leaks API key."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", 4)
    monkeypatch.setenv("NVD_API_KEY", "super-secret-api-key")

    response = Mock(spec=requests.Response)
    response.status_code = 404
    response.raise_for_status.side_effect = requests.HTTPError(
        "404 Client Error", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    exit_code = main.main(["--cve", "CVE-2021-44228"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "404" in captured.err
    assert "super-secret-api-key" not in captured.err
