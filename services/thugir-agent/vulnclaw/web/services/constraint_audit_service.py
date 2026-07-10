"""Constraint audit aggregation service for the Web UI backend."""

from __future__ import annotations

import json

from vulnclaw.config.settings import TARGETS_DIR, ensure_dirs
from vulnclaw.web.schemas import ConstraintAuditEventView, ConstraintAuditView


def get_constraint_audit(limit: int = 30) -> ConstraintAuditView:
    """Aggregate recent constraint audit events across target state."""
    ensure_dirs()
    events: list[ConstraintAuditEventView] = []
    by_source: dict[str, int] = {}
    by_code: dict[str, int] = {}
    high_severity = 0

    for state_path in TARGETS_DIR.glob("*/state.json"):
        try:
            raw = json.loads(state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        target = str(raw.get("target") or "unknown")
        for item in raw.get("constraint_violation_events", []):
            if not isinstance(item, dict):
                continue
            event = ConstraintAuditEventView(target=target, **item)
            events.append(event)
            by_source[event.source or "unknown"] = by_source.get(event.source or "unknown", 0) + 1
            by_code[event.code or "unknown"] = by_code.get(event.code or "unknown", 0) + 1
            if (event.severity or "").lower() == "high":
                high_severity += 1

    events.sort(key=lambda item: item.timestamp, reverse=True)
    return ConstraintAuditView(
        total_events=len(events),
        high_severity_events=high_severity,
        by_source=by_source,
        by_code=by_code,
        recent_events=events[:limit],
    )
