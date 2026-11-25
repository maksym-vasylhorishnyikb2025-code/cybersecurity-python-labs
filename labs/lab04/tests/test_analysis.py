"""Unit tests for labs.lab04.analysis (Variant 4)."""

import copy
from typing import Any

import pytest

from labs.lab04.analysis import build_report, extract_record


@pytest.mark.parametrize(
    ("score", "user_interaction", "expected_decision"),
    [
        (7.9, "NONE", "other"),
        (8.0, "NONE", "review"),
        (9.8, "NONE", "review"),
        (9.8, "REQUIRED", "other"),
    ],
)
def test_variant4_threshold_and_attribute(
    sample_payload: dict[str, Any],
    score: float,
    user_interaction: str,
    expected_decision: str,
) -> None:
    """Verify Variant 4 boundary (score >= 8.0 and userInteraction == NONE)."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cvss = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    cvss["baseScore"] = score
    cvss["userInteraction"] = user_interaction
    original = copy.deepcopy(sample_payload)

    record = extract_record(sample_payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", variant=4)

    assert sample_payload == original
    assert report["decision"] == expected_decision
    assert report["score"] == score
    assert report["observed"] == user_interaction
    assert report["rule"] == {
        "threshold": 8.0,
        "field": "userInteraction",
        "expected": "NONE",
    }


def test_not_found_empty_vulnerabilities() -> None:
    """Empty vulnerabilities list yields None record and not_found decision."""
    payload = {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    record = extract_record(payload, "CVE-2099-10001")
    assert record is None

    report = build_report(record, "CVE-2099-10001", variant=4)
    assert report == {
        "cve_id": "CVE-2099-10001",
        "variant": 4,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {
            "threshold": 8.0,
            "field": "userInteraction",
            "expected": "NONE",
        },
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_ignores_high_score(sample_payload: dict[str, Any]) -> None:
    """Rejected status produces rejected decision without score fields."""
    sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    record = extract_record(sample_payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", variant=4)

    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_vuln_status(sample_payload: dict[str, Any]) -> None:
    """Missing vulnStatus yields insufficient_data without score analysis."""
    del sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"]
    record = extract_record(sample_payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", variant=4)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_metrics(sample_payload: dict[str, Any]) -> None:
    """Missing metrics under Analyzed status yields insufficient_data."""
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    record = extract_record(sample_payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", variant=4)

    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_variant_field(sample_payload: dict[str, Any]) -> None:
    """Missing userInteraction in cvssData yields insufficient_data."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cvss = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    del cvss["userInteraction"]

    record = extract_record(sample_payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", variant=4)

    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("bad_value", [None, "INVALID", 123, True])
def test_invalid_variant_field_value_raises(
    sample_payload: dict[str, Any], bad_value: Any
) -> None:
    """Null or disallowed userInteraction value raises ValueError."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cvss = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    cvss["userInteraction"] = bad_value

    record = extract_record(sample_payload, "CVE-2099-10001")
    with pytest.raises(ValueError):
        build_report(record, "CVE-2099-10001", variant=4)


@pytest.mark.parametrize(
    "bad_score", ["9.8", True, -0.1, 10.1, float("nan"), float("inf")]
)
def test_invalid_base_score_raises(
    sample_payload: dict[str, Any], bad_score: Any
) -> None:
    """Non-numeric, bool, or out-of-range baseScore raises ValueError."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cvss = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    cvss["baseScore"] = bad_score

    with pytest.raises(ValueError):
        extract_record(sample_payload, "CVE-2099-10001")


def test_primary_metric_preferred(sample_payload: dict[str, Any]) -> None:
    """First Primary metric takes precedence over an earlier Secondary one."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    primary = cve["metrics"]["cvssMetricV31"][0]
    secondary = copy.deepcopy(primary)
    secondary["type"] = "Secondary"
    secondary["source"] = "secondary@example.invalid"
    secondary["cvssData"]["baseScore"] = 4.0
    secondary["cvssData"]["userInteraction"] = "REQUIRED"

    cve["metrics"]["cvssMetricV31"] = [secondary, primary]

    record = extract_record(sample_payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", variant=4)

    assert report["score"] == 9.8
    assert report["score_source"] == "nvd@nist.gov"
    assert report["observed"] == "NONE"
    assert report["decision"] == "review"


def test_fallback_to_first_metric(sample_payload: dict[str, Any]) -> None:
    """When no Primary rating exists, the first v3.1 metric is chosen."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    first = cve["metrics"]["cvssMetricV31"][0]
    first["type"] = "Secondary"
    first["source"] = "first@example.invalid"
    first["cvssData"]["baseScore"] = 6.5

    second = copy.deepcopy(first)
    second["source"] = "second@example.invalid"
    second["cvssData"]["baseScore"] = 9.9

    cve["metrics"]["cvssMetricV31"] = [first, second]

    record = extract_record(sample_payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", variant=4)

    assert report["score"] == 6.5
    assert report["score_source"] == "first@example.invalid"
    assert report["decision"] == "other"
