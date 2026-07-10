"""Helpers for server-sent event formatting."""

from __future__ import annotations

import json

from vulnclaw.web.schemas import TaskEvent


def encode_sse(event: TaskEvent) -> str:
    """Encode a task event as an SSE frame."""
    payload = json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
    return f"event: {event.event}\ndata: {payload}\n\n"
