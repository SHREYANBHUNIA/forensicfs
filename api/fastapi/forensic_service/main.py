from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException

from .engine import run_native_analysis
from .models import AnalysisRequest, CaseStatus
from .repository import CaseRepository

DATABASE_PATH = os.environ.get("FORENSIC_SQLITE_PATH", "./forensicfs-results.sqlite3")
repository = CaseRepository(DATABASE_PATH)


@asynccontextmanager
async def lifespan(_: FastAPI):
    repository.initialize()
    yield


app = FastAPI(title="ForensicFS Analysis Service", version="0.1.0", lifespan=lifespan)


def run_job(request: AnalysisRequest) -> None:
    repository.set_status(request.case_id, CaseStatus.ANALYZING)
    try:
        result = run_native_analysis(request)
        repository.save_result(result)
    except Exception as error:  # Retain a safe operator-visible message; do not expose signed URLs.
        repository.set_status(request.case_id, CaseStatus.FAILED, str(error)[:1000])


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/cases/analyze", status_code=202)
def submit_analysis(request: AnalysisRequest, background_tasks: BackgroundTasks) -> dict[str, str]:
    try:
        repository.queue_case(request)
    except Exception as error:
        raise HTTPException(status_code=409, detail="A case with this identifier already exists") from error
    background_tasks.add_task(run_job, request)
    return {"case_id": request.case_id, "status": CaseStatus.QUEUED.value}


@app.get("/v1/cases/{case_id}")
def get_case(case_id: str) -> dict:
    workspace = repository.get_case_workspace(case_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Case not found")
    return workspace
