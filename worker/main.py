"""Deep Scan worker - FastAPI service.

QStash POSTs Deep Scan jobs here (signed). We verify the signature, mark the scan running,
execute the capped Deep Scan (runner.run_deep_scan), write findings back to Supabase, and
mark the scan done. The worker is the ONLY component that imports thugir-node Python, and it
runs OUTSIDE Vercel (Render/Fly) because the engine shells out to nmap/nikto/nuclei.
"""
from __future__ import annotations

import os
import socket
import threading

from fastapi import FastAPI, Header, HTTPException, Request

import job_auth
import runner
import supabase_io as db
from target_guard import UnsafeTargetError, guard_target

app = FastAPI(title="Thugir Deep Scan Worker")
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


def _process(job: dict) -> None:
    scan_id = job["scanId"]
    target = job["targetUrl"]
    include_injection = bool(job.get("includeInjection", True))
    monitor_id = job.get("monitorId")
    previous_scan_id = job.get("previousScanId")

    db.update_scan(scan_id, status="running", worker_id=WORKER_ID, started_at=_now())

    def cancelled() -> bool:
        return db.get_scan_status(scan_id) == "killed"

    progress_log: list[str] = []
    try:
        rows = runner.run_deep_scan(
            target,
            include_injection=include_injection,
            progress=progress_log.append,
            cancelled=cancelled,
        )
        if cancelled():
            return  # admin killed it; status already 'killed'
        db.insert_findings(scan_id, rows)
        db.update_scan(scan_id, status="done", finished_at=_now())
        if monitor_id:
            _notify_monitor_complete(scan_id, monitor_id, previous_scan_id)
    except Exception as exc:
        db.update_scan(scan_id, status="failed", error=str(exc)[:500], finished_at=_now())


def _notify_monitor_complete(
    scan_id: str, monitor_id: str, previous_scan_id: str | None
) -> None:
    """Fire-and-forget callback so the web app can email scan deltas."""
    site = os.getenv("SITE_URL", os.getenv("NEXT_PUBLIC_SITE_URL", "")).rstrip("/")
    secret = os.getenv("WORKER_CALLBACK_SECRET", "")
    if not site or not secret:
        return
    import json

    payload = {
        "scanId": scan_id,
        "monitorId": monitor_id,
        "previousScanId": previous_scan_id,
    }
    try:
        import requests

        requests.post(
            f"{site}/api/worker/complete",
            headers={
                "Content-Type": "application/json",
                "X-Worker-Secret": secret,
            },
            json=payload,
            timeout=20,
        )
    except Exception:
        pass


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


@app.get("/health")
def health() -> dict:
    return {"ok": True, "worker": WORKER_ID}


@app.post("/run")
async def run(request: Request, upstash_signature: str | None = Header(default=None)) -> dict:
    body = await request.body()
    if not job_auth.verify_qstash(body, upstash_signature):
        raise HTTPException(status_code=401, detail="invalid signature")

    import json

    job = json.loads(body.decode("utf-8"))
    if not job.get("scanId") or not job.get("targetUrl"):
        raise HTTPException(status_code=400, detail="missing scanId/targetUrl")
    try:
        guard_target(job["targetUrl"])
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Run the (potentially minutes-long) scan in a background thread so QStash gets a fast 202.
    threading.Thread(target=_process, args=(job,), daemon=True).start()
    return {"accepted": True, "scanId": job["scanId"]}
