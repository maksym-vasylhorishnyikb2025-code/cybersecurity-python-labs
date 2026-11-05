import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, Body, HTTPException, Query, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead])
def read_records(
    category_id: int | None = Query(None, gt=0),
    status: Literal["new", "in_progress", "done"] | None = None,
    min_value: int | None = Query(None, ge=0),
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return repository.get_records(category_id, status, min_value, q, limit, offset)


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
)
def bulk_create_records(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
):
    try:
        inserted_ids = repository.bulk_create_records(records)
        return [repository.get_record(rid) for rid in inserted_ids]
    except sqlite3.IntegrityError as e:
        if "foreign key constraint" in str(e).lower():
            raise HTTPException(status_code=404, detail="Категорія не існує")
        raise HTTPException(status_code=409, detail="Дублікат у пакеті")


@router.get("/{record_id}", response_model=RecordRead)
def read_record(record_id: int):
    record = repository.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Не знайдено")
    return record


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(record: RecordCreate):
    try:
        rec_id = repository.create_record(record)
        return repository.get_record(rec_id)
    except sqlite3.IntegrityError as e:
        if "foreign key constraint" in str(e).lower():
            raise HTTPException(status_code=404, detail="Немає категорії")
        raise HTTPException(status_code=409, detail="Дублікат коду")


@router.put("/{record_id}", response_model=RecordRead)
def replace_record(record_id: int, record: RecordReplace):
    try:
        if not repository.update_record(record_id, record):
            raise HTTPException(status_code=404, detail="Не знайдено")
        return repository.get_record(record_id)
    except sqlite3.IntegrityError as e:
        if "foreign key constraint" in str(e).lower():
            raise HTTPException(status_code=404, detail="Немає категорії")
        raise HTTPException(status_code=409, detail="Дублікат коду")


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int):
    if not repository.delete_record(record_id):
        raise HTTPException(status_code=404, detail="Не знайдено")
