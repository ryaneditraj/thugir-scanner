"""Thin Supabase REST client for the worker.

Uses the service-role key to update scan status and insert findings. Kept dependency-light
(stdlib + requests, which thugir-node already depends on) so the worker stays small.
"""
from __future__ import annotations

import os
from typing import Any

import requests

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")


def _headers() -> dict[str, str]:
    return {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }


def update_scan(scan_id: str, **fields: Any) -> None:
    requests.patch(
        f"{SUPABASE_URL}/rest/v1/scans?id=eq.{scan_id}",
        headers=_headers(),
        json=fields,
        timeout=15,
    )


def get_scan_status(scan_id: str) -> str | None:
    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/scans?id=eq.{scan_id}&select=status",
        headers={**_headers(), "Accept": "application/json"},
        timeout=15,
    )
    try:
        rows = r.json()
        return rows[0]["status"] if rows else None
    except Exception:
        return None


def insert_findings(scan_id: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    payload = [{**row, "scan_id": scan_id} for row in rows]
    requests.post(
        f"{SUPABASE_URL}/rest/v1/findings",
        headers=_headers(),
        json=payload,
        timeout=30,
    )
