from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Header, HTTPException

from src.core.schemas import WorkerExecuteRequest, WorkerExecuteResponse
from src.distributed.worker_engine import WorkerEngine


app = FastAPI(title="Recon Worker", version="1.0.0")
engine = WorkerEngine(worker_id=os.getenv("WORKER_ID", "remote-worker"))


def require_api_key(x_api_key: str = Header(default="")) -> None:
    configured = os.getenv("WORKER_API_KEY", "")
    if not configured:
        raise HTTPException(status_code=500, detail="WORKER_API_KEY not configured")
    if x_api_key != configured:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/execute", response_model=WorkerExecuteResponse, dependencies=[Depends(require_api_key)])
async def execute_task(payload: WorkerExecuteRequest) -> WorkerExecuteResponse:
    result = await engine.execute(payload.task)
    return WorkerExecuteResponse(result=result)
