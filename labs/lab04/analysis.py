"""Validation and CVSS v3.1 rule evaluation for NVD CVE responses."""

import math
from typing import Any, TypeGuard

ALLOWED_CVSS_VALUES: dict[str, set[str]] = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}


def _is_dict(value: Any) -> TypeGuard[dict[str, Any]]:
    """Return True when value is a dictionary."""
    return isinstance(value, dict)


def _is_list(value: Any) -> TypeGuard[list[Any]]:
    """Return True when value is a list."""
    return isinstance(value, list)


def _is_str(value: Any) -> TypeGuard[str]:
    """Return True when value is a string."""
    return isinstance(value, str)


def _is_score_number(value: Any) -> TypeGuard[int | float]:
    """Return True when value is an int or float excluding bool."""
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _parse_optional_nonempty_str(container: dict[str, Any], key: str) -> str | None:
    """Validate an optional field that must be a non-empty string if present."""
    if key not in container:
        return None
    value = container[key]
    if not _is_str(value) or not value.strip():
        raise ValueError(f"Field '{key}' must be a non-empty string.")
    return value


def _extract_english_description(cve: dict[str, Any]) -> str | None:
    """Validate descriptions list and return the first non-empty English text."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not _is_list(descriptions):
        raise ValueError("Field 'descriptions' must be a list.")

    english_text: str | None = None
    for entry in descriptions:
        if not _is_dict(entry):
            raise ValueError("Each description entry must be a dict.")
        lang = entry.get("lang")
        value = entry.get("value")
        if not _is_str(lang) or not _is_str(value):
            raise ValueError("Description 'lang' and 'value' must be strings.")
        if english_text is None and lang == "en" and value.strip():
            english_text = value
    return english_text


def _select_v31_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Select Primary CVSS v3.1 metric or fall back to the first v3.1 entry."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not _is_dict(metrics):
        raise ValueError("Field 'metrics' must be a dict.")
    if "cvssMetricV31" not in metrics:
        return None
    metric_list = metrics["cvssMetricV31"]
    if not _is_list(metric_list):
        raise ValueError("Field 'cvssMetricV31' must be a list.")
    if not metric_list:
        return None

    for item in metric_list:
        if not _is_dict(item):
            raise ValueError("Each CVSS v3.1 metric entry must be a dict.")
    for item in metric_list:
        if item.get("type") == "Primary":
            return item
    return metric_list[0]


def _parse_score(cvss_data: dict[str, Any]) -> float:
    """Validate baseScore as a finite number within [0, 10] excluding bool."""
    if "baseScore" not in cvss_data:
        raise ValueError("Missing 'baseScore' in cvssData.")
    raw_score = cvss_data["baseScore"]
    if not _is_score_number(raw_score):
        raise ValueError("Field 'baseScore' must be a number.")
    score = float(raw_score)
    if not math.isfinite(score) or not (0.0 <= score <= 10.0):
        raise ValueError("Field 'baseScore' must be between 0 and 10.")
    return score


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Validate NVD payload and return an internal CVE record or None.

    Internal record structure:
        - cve_id (str): Requested CVE identifier.
        - description (str | None): First non-empty English description.
        - vuln_status (str | None): NVD vulnerability status.
        - cvss_version (str | None): CVSS version ("3.1") if rating is present.
        - score (float | None): Base score of the selected CVSS v3.1 rating.
        - score_source (str | None): Source of the selected CVSS v3.1 rating.
        - vector (str | None): Vector string of the selected CVSS v3.1 rating.
        - cvss_data (dict[str, Any] | None): Shallow copy of selected cvssData.
    """
    if not _is_dict(payload):
        raise ValueError("Response payload must be a dict.")
    vulnerabilities = payload.get("vulnerabilities")
    if not _is_list(vulnerabilities):
        raise ValueError("Payload must contain a 'vulnerabilities' list.")

    if len(vulnerabilities) > 1:
        raise ValueError("Expected at most one item in 'vulnerabilities'.")
    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    if not _is_dict(item) or not _is_dict(item.get("cve")):
        raise ValueError("Vulnerability item must contain a 'cve' dict.")

    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("CVE identifier in response does not match request.")

    vuln_status = _parse_optional_nonempty_str(cve, "vulnStatus")
    description = _extract_english_description(cve)

    if vuln_status is None or vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    selected = _select_v31_metric(cve)
    if selected is None:
        return {
            "cve_id": cve_id,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    cvss_data = selected.get("cvssData")
    if not _is_dict(cvss_data):
        raise ValueError("Selected metric must contain a 'cvssData' dict.")

    score = _parse_score(cvss_data)
    cvss_version = _parse_optional_nonempty_str(cvss_data, "version")
    if cvss_version is not None and cvss_version != "3.1":
        raise ValueError("Field 'cvssData.version' must equal '3.1'.")
    vector = _parse_optional_nonempty_str(cvss_data, "vectorString")
    score_source = _parse_optional_nonempty_str(selected, "source")

    return {
        "cve_id": cve_id,
        "description": description,
        "vuln_status": vuln_status,
        "cvss_version": cvss_version,
        "score": score,
        "score_source": score_source,
        "vector": vector,
        "cvss_data": dict(cvss_data),
    }


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Apply the variant rule to an extracted record and build a JSON report."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError("Variant number must be an integer from 1 to 15.")

    rule = dict(VARIANT_RULES[variant])

    if record is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": None,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "not_found",
        }

    if not _is_dict(record):
        raise ValueError("Record must be a dict or None.")
    if "cve_id" in record and record["cve_id"] != cve_id:
        raise ValueError("Record 'cve_id' does not match requested CVE.")

    description = record.get("description")
    vuln_status = record.get("vuln_status")

    if vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "rejected",
        }

    if vuln_status is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    score = record.get("score")
    cvss_data = record.get("cvss_data")
    if score is None or cvss_data is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    if not _is_dict(cvss_data):
        raise ValueError("Record 'cvss_data' must be a dict.")

    field = rule["field"]
    if field not in cvss_data:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": record.get("cvss_version"),
            "score": score,
            "score_source": record.get("score_source"),
            "vector": record.get("vector"),
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    observed = cvss_data[field]
    if not _is_str(observed) or observed not in ALLOWED_CVSS_VALUES[field]:
        raise ValueError(f"Invalid value for '{field}'.")

    decision = (
        "review"
        if (score >= rule["threshold"] and observed == rule["expected"])
        else "other"
    )

    return {
        "cve_id": cve_id,
        "variant": variant,
        "description": description,
        "vuln_status": vuln_status,
        "cvss_version": record.get("cvss_version"),
        "score": score,
        "score_source": record.get("score_source"),
        "vector": record.get("vector"),
        "rule": rule,
        "observed": observed,
        "decision": decision,
    }
