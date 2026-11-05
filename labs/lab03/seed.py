import json
import logging
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
SEED_PATH = BASE_DIR / "data" / "seed.json"


def seed_database() -> None:
    initialize_database()
    if not SEED_PATH.exists():
        logger.error("Файл seed.json не знайдено.")
        return
    with open(SEED_PATH, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    with closing(get_connection()) as connection:
        try:
            count = connection.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
            if count > 0:
                logger.info("База вже містить дані. Скасовано.")
                return
            with connection:
                for cat in data["categories"]:
                    connection.execute(
                        "INSERT INTO categories (id, name) VALUES (?, ?)",
                        (cat["id"], cat["name"]),
                    )
                for rec in data["records"]:
                    connection.execute(
                        "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                        (
                            rec["code"],
                            rec["title"],
                            rec["category_id"],
                            rec["value"],
                            rec["status"],
                        ),
                    )
            logger.info("Успішно заповнено.")
        except Exception as e:  # noqa: BLE001
            logger.error(f"Помилка: {e}")


if __name__ == "__main__":
    seed_database()
