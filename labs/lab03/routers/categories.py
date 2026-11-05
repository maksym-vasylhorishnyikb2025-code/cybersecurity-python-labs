import sqlite3

from fastapi import APIRouter, HTTPException, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get("", response_model=list[CategoryRead])
def read_categories():
    return repository.get_categories()


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(category: CategoryCreate):
    try:
        cat_id = repository.create_category(category)
        return {"id": cat_id, **category.model_dump()}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Категорія існує")


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int):
    try:
        if not repository.delete_category(category_id):
            raise HTTPException(status_code=404, detail="Не знайдено")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Містить записи")
