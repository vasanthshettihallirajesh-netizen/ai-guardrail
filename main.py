"""
main.py — FastAPI backend for AI Guardrail.

Endpoints:
    POST /scan              scan a single message, log it, optionally block
    GET  /scans              list recent scans
    GET  /scans/stats        risk-level counts
    POST /test-runs          trigger a benchmark run against test_cases/
    GET  /test-runs          list past runs
    GET  /test-runs/{id}     full detail for one run
    GET  /test-runs/trend    bypass rate over time, for charting
    GET  /health              liveness check

Run:
    pip install -r requirements.txt
    uvicorn app.main:app --reload
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Literal

from app import db
from firewall.detector import Detector
import runner as benchmark_runner

app = FastAPI(
    title="AI Guardrail API",
    description="Prompt injection / jailbreak detection firewall + benchmark backend",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    db.init_db()


class ScanRequest(BaseModel):
    text: str
    profile: Literal["strict", "balanced", "permissive"] = "balanced"
    client_id: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: int
    risk: str
    score: float
    blocked: bool
    matched_categories: list
    signals: dict


class TestRunRequest(BaseModel):
    mode: Literal["mock", "api"] = "mock"
    model: str = "claude-sonnet-4-6"
    firewall: bool = True
    profile: Literal["strict", "balanced", "permissive"] = "balanced"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan_message(req: ScanRequest):
    detector = Detector(profile=req.profile)
    result = detector.scan(req.text)
    blocked = result["risk"] == "high"

    scan_id = db.record_scan(
        input_text=req.text,
        profile=req.profile,
        scan_result=result,
        blocked=blocked,
        client_id=req.client_id,
    )

    return ScanResponse(
        scan_id=scan_id,
        risk=result["risk"],
        score=result["score"],
        blocked=blocked,
        matched_categories=result["matched_categories"],
        signals=result["signals"],
    )


@app.get("/scans")
def get_scans(limit: int = Query(50, le=500), offset: int = 0):
    return db.list_scans(limit=limit, offset=offset)


@app.get("/scans/stats")
def scan_stats(since_hours: Optional[float] = None):
    import time
    since = time.time() - since_hours * 3600 if since_hours else None
    return db.get_scan_stats(since=since)


@app.post("/test-runs")
def create_test_run(req: TestRunRequest):
    try:
        results = benchmark_runner.run(
            mode=req.mode,
            model=req.model,
            use_firewall=req.firewall,
            profile=req.profile,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    run_id = db.record_test_run(
        mode=req.mode,
        model=req.model if req.mode == "api" else None,
        profile=req.profile,
        firewall_enabled=req.firewall,
        results=results,
    )
    return db.get_test_run(run_id)


@app.get("/test-runs")
def get_test_runs(limit: int = Query(50, le=500)):
    return db.list_test_runs(limit=limit)


@app.get("/test-runs/trend")
def get_trend(limit: int = Query(30, le=500)):
    return db.get_bypass_trend(limit=limit)


@app.get("/test-runs/{run_id}")
def get_test_run(run_id: int):
    run = db.get_test_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run
