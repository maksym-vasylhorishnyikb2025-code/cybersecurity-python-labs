"""Unit tests for labs.lab04.api_client."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_without_key() -> None:
    """Without NVD_API_KEY, only Accept header is returned."""
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_whitespace_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only NVD_API_KEY is treated as absent."""
    monkeypatch.setenv("NVD_API_KEY", "   ")
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_with_fake_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-empty NVD_API_KEY is stripped and passed in apiKey header."""
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key-123",
    }


def test_fetch_response_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """fetch_response sends expected GET parameters, headers, and timeout."""
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    result = api_client.fetch_response("CVE-2099-10001")
    assert result == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_response_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP error raised by raise_for_status propagates to caller."""
    response = Mock(spec=requests.Response)
    response.status_code = 404
    response.raise_for_status.side_effect = requests.HTTPError(
        "Not Found", response=response
    )

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_redirect_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-200 status (e.g., 302) raises HTTPError when redirects disabled."""
    response = Mock(spec=requests.Response)
    response.status_code = 302
    response.raise_for_status.return_value = None

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_network_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Network Timeout exception propagates without catching."""
    fake_get = Mock(side_effect=requests.Timeout("Connection timed out"))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.Timeout):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid JSON body raises JSONDecodeError."""
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )

    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")
