from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Регулярний вираз для подій Failed password та Accepted password з Linux auth.log
AUTH_LOG_REGEX: re.Pattern[str] = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)


@dataclass(frozen=True)
class AuthEvent:
    """Незмінний клас події аутентифікації."""

    timestamp: datetime
    status: str
    username: str
    ip: str


@dataclass
class BruteforceIncident:
    """Клас інциденту виявлення атаки Bruteforce."""

    ip: str
    total_failures: int
    target_users: list[str]
    first_seen: str
    last_seen: str


def parse_log_line(line: str, current_year: int) -> AuthEvent | None:
    """Парсинг рядка журналу за допомогою регулярного виразу."""
    match = AUTH_LOG_REGEX.search(line)
    if not match:
        return None
    data = match.groupdict()
    date_str = f"{current_year} {data['month']} {int(data['day']):02d} {data['time']}"
    try:
        ts = datetime.strptime(date_str, "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
    return AuthEvent(
        timestamp=ts,
        status=data["status"],
        username=data["user"],
        ip=data["ip"],
    )


def detect_bruteforce(
    events: list[AuthEvent],
    threshold: int,
    window_sec: int,
) -> list[BruteforceIncident]:
    """Агрегація подій через defaultdict та пошук атак у ковзному часовому вікні."""
    ip_failed_events: defaultdict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        if ev.status == "Failed":
            ip_failed_events[ev.ip].append(ev)

    incidents: list[BruteforceIncident] = []
    for ip, fails in ip_failed_events.items():
        fails.sort(key=lambda x: x.timestamp)
        is_attacker = False
        left = 0
        for right in range(len(fails)):
            while (
                fails[right].timestamp - fails[left].timestamp
            ).total_seconds() > window_sec:
                left += 1
            if (right - left + 1) >= threshold:
                is_attacker = True
                break

        if is_attacker:
            users = sorted({ev.username for ev in fails})
            incidents.append(
                BruteforceIncident(
                    ip=ip,
                    total_failures=len(fails),
                    target_users=users,
                    first_seen=fails[0].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen=fails[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                )
            )

    incidents.sort(key=lambda x: x.total_failures, reverse=True)
    return incidents


def export_report(
    output_path: Path,
    incidents: list[BruteforceIncident],
    total_processed: int,
    time_range: tuple[str, str],
) -> None:
    """Експорт підсумкового JSON-звіту зі списком блокувань."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "metadata": {
            "processed_lines": total_processed,
            "time_range": f"{time_range[0]} - {time_range[1]}",
            "detected_attacks": len(incidents),
        },
        "recommended_blocklist": [inc.ip for inc in incidents],
        "incidents": [asdict(inc) for inc in incidents],
    }
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def parse_args(cmd_args: list[str] | None = None) -> argparse.Namespace:
    default_log = Path("labs/lab02/data/data_v04/auth.log")
    parser = argparse.ArgumentParser(
        description="Аналізатор журналів аутентифікації SSH та детекція Bruteforce (Варіант 4)"
    )
    parser.add_argument(
        "--auth-log",
        type=Path,
        default=default_log,
        help="Шлях до файлу auth.log (за замовчуванням: labs/lab02/data/data_v04/auth.log)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Поріг невдалих спроб для спрацювання (дефолт: 5)",
    )
    parser.add_argument(
        "--window-min",
        type=int,
        default=5,
        help="Часове вікно аналізу у хвилинах (дефолт: 5)",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("labs/lab02/data/blocklist_ips.json"),
        help="Шлях для збереження JSON-звіту",
    )
    return parser.parse_args(cmd_args)


def run_analyzer(cmd_args: list[str] | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    args = parse_args(cmd_args)
    if not args.auth_log.exists():
        logger.error("Файл журналу не знайдено: %s", args.auth_log)
        sys.exit(1)

    logger.info("Analyzing authentication events in %s...", args.auth_log)
    current_year = datetime.now(tz=timezone.utc).year
    events: list[AuthEvent] = []
    total_lines = 0

    with args.auth_log.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            ev = parse_log_line(line, current_year)
            if ev:
                events.append(ev)

    if not events:
        logger.warning("Не виявлено валідних подій sshd у файлі.")
        return

    events.sort(key=lambda x: x.timestamp)
    time_start = events[0].timestamp.strftime("%Y-%m-%d %H:%M:%S")
    time_end = events[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S")

    logger.info(
        "Processed %d lines (Time range: %s - %s)",
        total_lines,
        time_start,
        time_end,
    )

    incidents = detect_bruteforce(
        events=events,
        threshold=args.threshold,
        window_sec=args.window_min * 60,
    )

    print("\n=== SSH Bruteforce Detection Results ===")
    print(
        f"Failed Attempts Threshold: >={args.threshold} attempts in {args.window_min} minutes"
    )
    for inc in incidents:
        users_str = ", ".join(inc.target_users[:5])
        if len(inc.target_users) > 5:
            users_str += f" (+{len(inc.target_users) - 5} more)"
        print(
            f"[ALERT] Bruteforce Detected! IP: {inc.ip:<15} | "
            f"Total Failures: {inc.total_failures:<4} | Target Users: {users_str}"
        )
        logger.error(
            "Attack signature matched: host %s executed bruteforce attack.", inc.ip
        )

    print("\n=== Recommended Blocklist (IPs) ===")
    for inc in incidents:
        print(inc.ip)

    try:
        export_report(args.output_json, incidents, total_lines, (time_start, time_end))
        logger.info("Exported blocklist to %s", args.output_json)
    except OSError as err:
        logger.error("Не вдалося зберегти звіт у JSON: %s", err)


if __name__ == "__main__":
    run_analyzer()
