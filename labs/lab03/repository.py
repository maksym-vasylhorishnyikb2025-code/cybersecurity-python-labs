from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection
from labs.lab03.schemas import CategoryCreate, RecordCreate, RecordReplace


def create_category(category: CategoryCreate) -> int:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO categories (name) VALUES (?)", (category.name,)
        )
        return cursor.lastrowid


def get_categories() -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        cursor = conn.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]


def delete_category(category_id: int) -> bool:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        return cursor.rowcount > 0


def create_record(record: RecordCreate) -> int:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
            (
                record.code,
                record.title,
                record.category_id,
                record.value,
                record.status,
            ),
        )
        return cursor.lastrowid


def get_record(record_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name FROM records r JOIN categories c ON r.category_id = c.id WHERE r.id = ?",
            (record_id,),
        )
        row = cursor.fetchone()
        return (
            {
                "id": row[0],
                "code": row[1],
                "title": row[2],
                "category_id": row[3],
                "value": row[4],
                "status": row[5],
                "category_name": row[6],
            }
            if row
            else None
        )


def get_records(
    category_id=None, status=None, min_value=None, q=None, limit=20, offset=0
) -> list[dict[str, Any]]:
    query = "SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name FROM records r JOIN categories c ON r.category_id = c.id WHERE 1=1"
    params = []
    if category_id is not None:
        query += " AND r.category_id = ?"
        params.append(category_id)
    if status is not None:
        query += " AND r.status = ?"
        params.append(status)
    if min_value is not None:
        query += " AND r.value >= ?"
        params.append(min_value)
    if q is not None:
        query += " AND instr(r.title, ?) > 0"
        params.append(q)
    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as conn:
        cursor = conn.execute(query, tuple(params))
        return [
            {
                "id": r[0],
                "code": r[1],
                "title": r[2],
                "category_id": r[3],
                "value": r[4],
                "status": r[5],
                "category_name": r[6],
            }
            for r in cursor.fetchall()
        ]


def update_record(record_id: int, record: RecordReplace) -> bool:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute(
            "UPDATE records SET code=?, title=?, category_id=?, value=?, status=? WHERE id=?",
            (
                record.code,
                record.title,
                record.category_id,
                record.value,
                record.status,
                record_id,
            ),
        )
        return cursor.rowcount > 0


def delete_record(record_id: int) -> bool:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        return cursor.rowcount > 0


def bulk_create_records(records: list[RecordCreate]) -> list[int]:
    inserted_ids = []
    with closing(get_connection()) as conn, conn:
        for record in records:
            cursor = conn.execute(
                "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                (
                    record.code,
                    record.title,
                    record.category_id,
                    record.value,
                    record.status,
                ),
            )
            inserted_ids.append(cursor.lastrowid)
    return inserted_ids
