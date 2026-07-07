"""Deep Scan runner — full TCSF aggressive pipeline with hard time caps.

Uses thugir-node max-power investigation (crawl, active probes, authz, nuclei,
LLM amplify, sqlmap, exploit confirmation) so commercial Deep Scans find real
vulns, not just headers. Falls back to lighter stages if max-power fails.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

def _resolve_engine_root() -> Path:
    """Locate the thugir-framework engine in both layouts:

    - split scanner repo: framework is a git submodule at <scanner_root>/engine
    - monorepo:           framework lives at <repo_root>/thugir-node

    THUGIR_ENGINE_ROOT overrides everything (used in production/containers).
    """
    env = os.getenv("THUGIR_ENGINE_ROOT")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    candidates = [
        here.parents[1] / "engine",       # split repo: submodule at <scanner_root>/engine
        here.parents[2] / "thugir-node",  # monorepo: sibling of app/
        here.parents[1] / "thugir-node",
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


ENGINE_ROOT = _resolve_engine_root()
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))

MAX_RUNTIME_S = int(os.getenv("DEEP_MAX_RUNTIME_S", "420"))
API_MAX_ENDPOINTS = int(os.getenv("DEEP_API_MAX_ENDPOINTS", "400"))
RUN_EXTERNAL_TOOLS = os.getenv("DEEP_RUN_EXTERNAL_TOOLS", "1") == "1"
RUN_NUCLEI = os.getenv("DEEP_RUN_NUCLEI", "1") == "1"
WEB_TIMEOUT_S = int(os.getenv("DEEP_WEB_TIMEOUT_S", "25"))
# Prefer full aggressive pipeline (default ON).
USE_MAX_POWER = os.getenv("DEEP_USE_MAX_POWER", "1") == "1"

ProgressFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


def _classify_tier(finding: dict[str, Any]) -> str:
    ftype = (finding.get("finding_type") or finding.get("category") or "").lower()
    title = (finding.get("title") or "").lower()
    free_markers = ("header", "secret", ".env", ".git", "source map", "tls", "cookie")
    if any(m in ftype or m in title for m in free_markers):
        return "free"
    return "deep"


def _severity(finding: dict[str, Any]) -> str:
    sev = (finding.get("severity") or "info").lower()
    return sev if sev in {"critical", "high", "medium", "low", "info"} else "info"


def _to_row(finding: dict[str, Any]) -> dict[str, Any]:
    title = finding.get("title") or finding.get("name") or "Finding"
    impact = (
        finding.get("impact")
        or finding.get("business_impact")
        or finding.get("description")
        or title
    )
    remediation = finding.get("recommendation") or finding.get("remediation")
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    return {
        "category": finding.get("finding_type") or finding.get("category") or "general",
        "title": str(title)[:300],
        "severity": _severity(finding),
        "tier_required": _classify_tier(finding),
        "impact_oneline": str(impact)[:280],
        "evidence_json": {
            "evidence": finding.get("evidence") or finding.get("evidence_bundle"),
            "source": finding.get("source") or finding.get("source_tool") or meta.get("source"),
            "url": meta.get("url") or finding.get("url") or finding.get("target") or finding.get("device_ip"),
            "cve_id": finding.get("cve_id"),
            "status": finding.get("validation_status") or finding.get("status"),
            "payload": meta.get("payload"),
            "param": meta.get("param") or meta.get("param_name"),
        },
        "remediation_json": {"summary": str(remediation)} if remediation else None,
        "fix_prompt": finding.get("fix_prompt"),
        "confidence": float(finding.get("confidence") or finding.get("final_confidence") or 0.5),
        "engine_status": finding.get("validation_status") or finding.get("status"),
    }


def _run_max_power(target_url: str, progress: ProgressFn, cancelled: Callable[[], bool]) -> list[dict[str, Any]]:
    """Full aggressive TCSF investigation — primary Deep Scan path."""
    os.environ.setdefault("TCSF_MAX_POWER", "1")
    os.environ.setdefault("TCSF_POWER_MODE", "aggressive")
    os.environ.setdefault("TCSF_API_MAX_ENDPOINTS", str(API_MAX_ENDPOINTS))
    # Cap power rounds for commercial SLA.
    os.environ.setdefault("TCSF_POWER_ROUNDS", "8")

    from tcsf.power.max_power_run import run_max_power_investigation
    from tcsf.power.power_mode import apply_investigation_power_defaults

    apply_investigation_power_defaults()

    def on_progress(event: dict[str, Any]) -> None:
        if cancelled():
            return
        msg = event.get("message") or event.get("stage") or event.get("type") or ""
        if msg:
            progress(str(msg)[:200])

    progress("max_power_start")
    result = run_max_power_investigation(
        target=target_url,
        goal="commercial deep scan — maximize verified vulnerabilities",
        mode="aggressive",
        include_network=False,
        data_dir=str(ENGINE_ROOT),
        on_progress=on_progress,
        persist=False,
    )
    ws = result.get("workspace") or {}
    report = result.get("report") or {}
    findings = report.get("findings") or ws.get("findings") or []
    progress(f"max_power_done:{len(findings)}")
    return list(findings)


def _run_fallback(
    target_url: str,
    *,
    include_injection: bool,
    progress: ProgressFn,
    cancelled: Callable[[], bool],
    started: float,
) -> list[dict[str, Any]]:
    """Lighter path if max-power fails — still more than headers-only."""
    raw: list[dict[str, Any]] = []

    def time_left() -> float:
        return MAX_RUNTIME_S - (time.time() - started)

    if not cancelled() and time_left() > 0:
        progress("web_surface")
        try:
            from modules.deep_vuln_scan import deep_vuln_scan

            # Explicit power=False — we already tried max-power; avoid recursion.
            web = deep_vuln_scan(
                target_url,
                run_external_tools=RUN_EXTERNAL_TOOLS,
                run_nuclei=RUN_NUCLEI,
                timeout=WEB_TIMEOUT_S,
                power=False,
            )
            raw.extend(web.get("findings", []) or [])
        except Exception as exc:
            progress(f"web_surface_error:{exc}")

    if not cancelled() and time_left() > 0:
        progress("api_security")
        try:
            from modules.api_reachability import APIScanConfig, scan_api

            cfg = APIScanConfig(base_url=target_url, max_endpoints=API_MAX_ENDPOINTS)
            api = scan_api(cfg)
            raw.extend(api.get("findings", []) or [])
        except Exception as exc:
            progress(f"api_security_error:{exc}")

    if include_injection and not cancelled() and time_left() > 0:
        progress("active_probe")
        try:
            from tcsf.power.web_surface import run_web_surface_stage, run_active_probe_stage

            surface = run_web_surface_stage(target_url)
            inputs = surface.get("inputs") or []
            active = run_active_probe_stage(inputs, investigation_id="worker_deep")
            raw.extend(active.get("findings") or [])
            from tcsf.power.business_logic_probe import run_business_logic_probe
            from tcsf.power.active_prober import inputs_from_dicts

            biz = run_business_logic_probe(inputs_from_dicts(inputs))
            raw.extend(biz.get("findings") or [])
        except Exception as exc:
            progress(f"active_probe_error:{exc}")

    return raw


def run_deep_scan(
    target_url: str,
    *,
    include_injection: bool = True,
    progress: ProgressFn = _noop,
    cancelled: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run Deep Scan and return normalized finding rows ready for insert."""
    cancelled = cancelled or (lambda: False)
    started = time.time()
    raw: list[dict[str, Any]] = []

    if USE_MAX_POWER and not cancelled():
        try:
            raw = _run_max_power(target_url, progress, cancelled)
        except Exception as exc:
            progress(f"max_power_error:{exc}")
            raw = []

    if not raw and not cancelled():
        progress("fallback_pipeline")
        raw = _run_fallback(
            target_url,
            include_injection=include_injection,
            progress=progress,
            cancelled=cancelled,
            started=started,
        )

    progress("finalize")
    try:
        from nexus.finding_quality import finalize_findings

        finalized, _meta = finalize_findings(raw, customer_id="scanner-app")
    except Exception:
        finalized = raw

    rows = [_to_row(f) for f in finalized]
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for r in rows:
        ev = r.get("evidence_json") or {}
        # Dedup on the finding identity (title+severity) AND where/what it hit (url+param),
        # so the same class of bug on distinct endpoints/params is kept as separate findings.
        key = (
            r["title"],
            r["severity"],
            str(ev.get("url") or ""),
            str(ev.get("param") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    progress(f"findings:{len(unique)}")
    return unique
