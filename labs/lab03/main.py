from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared import student


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="Облік подій автентифікації", lifespan=lifespan)
app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/student")
def get_student_info():
    return {
        "student_name": student.student_name,
        "group_name": student.group_name,
        "variant_number": student.variant_number,
    }
