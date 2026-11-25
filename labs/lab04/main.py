"""CLI entry point for Lab 04 NVD CVE analyzer."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> Any:
    """Read and parse a UTF-8 JSON file from disk."""
    raw_text = Path(path).read_text(encoding="utf-8")
    return json.loads(raw_text)


def _is_valid_variant(value: Any) -> bool:
    """Validate that variant number is an integer in range 1..15."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 15


def _parse_cve(value: str) -> str:
    """Validate CVE identifier format for argparse."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "CVE identifier must match CVE-YYYY-NNNN (uppercase)."
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Fetch and evaluate an NVD CVE record."
    )
    parser.add_argument(
        "--cve",
        required=True,
        type=_parse_cve,
        help="Target CVE identifier (e.g., CVE-2021-44228).",
    )
    parser.add_argument(
        "--input",
        dest="input_path",
        default=None,
        help="Optional path to a local NVD JSON file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI utility and return an exit status code."""
    if not _is_valid_variant(VARIANT_NUMBER):
        print(
            "Error: VARIANT_NUMBER must be an integer between 1 and 15.",
            file=sys.stderr,
        )
        return 2

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.input_path is not None:
            payload = load_response(args.input_path)
        else:
            payload = api_client.fetch_response(args.cve)
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except requests.exceptions.Timeout:
        print("Error: request to NVD API timed out.", file=sys.stderr)
        return 1
    except requests.exceptions.ConnectionError:
        print("Error: failed to connect to NVD API.", file=sys.stderr)
        return 1
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        print(
            f"Error: NVD API returned HTTP error (status {status}).",
            file=sys.stderr,
        )
        return 1
    except requests.exceptions.RequestException:
        print("Error: network request to NVD API failed.", file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError):
        print("Error: failed to read local input file.", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("Error: response is not valid JSON.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: invalid response structure ({exc}).", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
