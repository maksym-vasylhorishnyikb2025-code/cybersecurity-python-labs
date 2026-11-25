"""HTTP client for querying the NVD CVE 2.0 API."""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT: tuple[float, float] = (3.05, 10)


def build_headers() -> dict[str, str]:
    """Build HTTP headers for NVD API requests without exposing secrets."""
    headers: dict[str, str] = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> Any:
    """Perform a single GET request to NVD API and return decoded JSON."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise requests.HTTPError(
            f"Unexpected HTTP status: {response.status_code}",
            response=response,
        )
    return response.json()
