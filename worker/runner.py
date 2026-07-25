"""Deep Scan runner — commercial embed of TCSF (Thugir Cognitive Security Framework).

Primary path (when thugir-node is present):
  TCSF max-power aggressive investigation (crawl, Strike/VulnClaw probes when available,
  authz, nuclei, LLM amplify, sqlmap, exploit confirmation) under commercial SLA caps.

Falls back to lighter module stages if max-power / runtime fails.
Findings are normalized with evidence verdicts (confirmed|likely|inconclusive|…) so the
product UI can trust High/Critical claims.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

ProgressFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


def _resolve_engine_root() -> Path:
    """Locate thugir-node (TCSF engine).

    Search order:
      1. THUGIR_ENGINE_ROOT (containers / Render)
      2. <scanner>/engine          (scripts/sync-engine.sh sparse checkout)
      3. sibling THUGIR LABS/thugir-node
      4. monorepo ../thugir-node
    """
    env = os.getenv("THUGIR_ENGINE_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    here = Path(__file__).resolve()
    scanner_root = here.parents[1]
    home = Path.home()
    candidates = [
        scanner_root / "engine",
        home / "THUGIR LABS" / "thugir-node",
        here.parents[2] / "thugir-node",
        scanner_root / "thugir-node",
    ]
    for c in candidates:
        if (c / "tcsf").is_dir() or (c / "nexus").is_dir():
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
USE_MAX_POWER = os.getenv("DEEP_USE_MAX_POWER", "1") == "1"
# Prefer portable TcsfRuntime when available (thugirlabs.com Jul 2026+).
USE_TCSF_RUNTIME = os.getenv("DEEP_USE_TCSF_RUNTIME", "1") == "1"
PRODUCT_ID = os.getenv("TCSF_PRODUCT_ID", "thugir-scanner")


def _apply_commercial_tcsf_env() -> None:
    """SLA + precision gates for the vibe-app Deep Scan product (not Mission Control)."""
    os.environ.setdefault("TCSF_MAX_POWER", "1")
    os.environ.setdefault("TCSF_POWER_MODE", "aggressive")
    os.environ.setdefault("TCSF_PRECISION_MODE", "1")  # High/Critical need exploit proof
    os.environ.setdefault("TCSF_API_MAX_ENDPOINTS", str(API_MAX_ENDPOINTS))
    os.environ.setdefault("TCSF_POWER_ROUNDS", "8")  # commercial wall-clock
    os.environ.setdefault("TCSF_PRODUCT_ID", PRODUCT_ID)
    # Skip enterprise surfaces irrelevant to Lovable/Bolt/v0 ICP
    os.environ.setdefault("TCSF_SKIP_M365", "1")
    os.environ.setdefault("TCSF_SKIP_CLOUD", "1")


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


def _enrich_verdicts(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach TCSF EvidenceVerdict when the engine ships the verdict plane."""
    try:
        from tcsf.evidence.verdict import assign_verdicts

        return assign_verdicts(findings)
    except Exception:
        return findings


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
    verdict = finding.get("verdict") if isinstance(finding.get("verdict"), dict) else None
    evidence_verdict = finding.get("evidence_verdict") or (verdict or {}).get("verdict")
    proof = (verdict or {}).get("proof") if verdict else None

    engine_status = (
        evidence_verdict
        or finding.get("validation_status")
        or finding.get("status")
    )

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
            "evidence_verdict": evidence_verdict,
            "verdict": verdict,
            "proof": proof,
        },
        "remediation_json": {"summary": str(remediation)} if remediation else None,
        "fix_prompt": finding.get("fix_prompt"),
        "confidence": float(finding.get("confidence") or finding.get("final_confidence") or 0.5),
        "engine_status": engine_status,
    }


def _findings_from_kernel_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    ws = result.get("workspace") or {}
    report = result.get("report") or {}
    return list(report.get("findings") or ws.get("findings") or [])


def _run_via_runtime(
    target_url: str, progress: ProgressFn, cancelled: Callable[[], bool]
) -> list[dict[str, Any]] | None:
    """Portable TcsfRuntime.investigate — preferred when available on engine tip."""
    try:
        from tcsf.runtime import RuntimeConfig, TcsfRuntime
        from tcsf.power.power_mode import apply_investigation_power_defaults
    except Exception:
        return None

    apply_investigation_power_defaults()

    def on_progress(event: dict[str, Any]) -> None:
        if cancelled():
            return
        msg = event.get("message") or event.get("stage") or event.get("type") or ""
        if msg:
            progress(str(msg)[:200])

    progress("tcsf_runtime_start")
    cfg = RuntimeConfig(
        data_dir=str(ENGINE_ROOT),
        include_network=False,
        persist=False,
        product_id=PRODUCT_ID,
        enable_reflection=True,
        enable_experiments=True,
    )
    runtime = TcsfRuntime(config=cfg)
    result = runtime.investigate(
        target_url,
        goal="commercial deep scan — maximize verified vulnerabilities on AI-built apps",
        on_progress=on_progress,
        config=cfg,
    )
    findings = list(result.findings or [])
    if not findings and isinstance(result.raw, dict):
        findings = _findings_from_kernel_result(result.raw)
    progress(f"tcsf_runtime_done:{len(findings)}:confirmed={result.confirmed_count}")
    return findings


def _run_max_power(
    target_url: str, progress: ProgressFn, cancelled: Callable[[], bool]
) -> list[dict[str, Any]]:
    """Aggressive max-power investigation — primary Deep Scan path."""
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
        goal="commercial deep scan — maximize verified vulnerabilities on AI-built apps",
        mode="aggressive",
        include_network=False,
        data_dir=str(ENGINE_ROOT),
        on_progress=on_progress,
        persist=False,
    )
    findings = _findings_from_kernel_result(result)
    progress(f"max_power_done:{len(findings)}")
    return findings


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

    # Prefer Strike library when present (thugirlabs.com tip); else classic probes.
    if include_injection and not cancelled() and time_left() > 0:
        progress("active_probe")
        try:
            strike_findings: list[dict[str, Any]] = []
            try:
                from tcsf.power.strike_probe import run_strike_probe_stage

                surface_inputs: list[dict[str, Any]] = []
                try:
                    from tcsf.power.web_surface import run_web_surface_stage

                    surface = run_web_surface_stage(target_url)
                    surface_inputs = list(surface.get("inputs") or [])
                except Exception:
                    surface_inputs = []
                strike = run_strike_probe_stage(
                    surface_inputs,
                    target=target_url,
                    investigation_id="worker_deep",
                    deep=True,
                )
                strike_findings = list(strike.get("findings") or [])
            except Exception:
                strike_findings = []

            if strike_findings:
                raw.extend(strike_findings)
            else:
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

    if not (ENGINE_ROOT / "tcsf").is_dir() and not (ENGINE_ROOT / "nexus").is_dir():
        progress(f"engine_missing:{ENGINE_ROOT} — run scripts/sync-engine.sh")

    if USE_MAX_POWER and not cancelled():
        _apply_commercial_tcsf_env()
        try:
            if USE_TCSF_RUNTIME:
                via_rt = _run_via_runtime(target_url, progress, cancelled)
                if via_rt is not None:
                    raw = via_rt
            if not raw:
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
    raw = _enrich_verdicts(raw)
    try:
        from nexus.finding_quality import finalize_findings

        finalized, _meta = finalize_findings(raw, customer_id=PRODUCT_ID)
    except Exception:
        finalized = raw

    # Re-attach verdicts after finalize (quality gate may strip unknown keys).
    finalized = _enrich_verdicts(list(finalized))

    rows = [_to_row(f) for f in finalized]
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for r in rows:
        ev = r.get("evidence_json") or {}
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
