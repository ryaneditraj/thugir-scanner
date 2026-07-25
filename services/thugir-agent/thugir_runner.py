#!/usr/bin/env python3
"""Thugir ↔ VulnClaw JSON bridge.

Reads a scan request from stdin, runs VulnClaw headless, prints JSON to stdout.

Input (stdin JSON):
  {
    "url": "https://target.example.com",
    "scan_mode": "quick|standard|deep",
    "command": "optional natural-language task",
    "api_key": "...",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o",
    "provider": "openai",
    "timeout_seconds": 600
  }

Output (stdout JSON):
  {
    "ok": true,
    "target": "...",
    "scan_mode": "quick",
    "exit_code": 0,
    "exit_meaning": "...",
    "summary": { ... },
    "findings": [ ... ],
    "report_path": "...",
    "run_dir": "...",
    "error": null
  }
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
RUNS_ROOT = ROOT / ".thugir-runs"
CONFIG_DIR = ROOT / ".thugir-config"


def _configure_env(req: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["VULNCLAW_CONFIG_DIR"] = str(CONFIG_DIR)
    env["VULNCLAW_RUNS_DIR"] = str(RUNS_ROOT)
    env["VULNCLAW_SESSION_RUNS_DIR"] = str(RUNS_ROOT)

    if req.get("api_key"):
        env["VULNCLAW_LLM_API_KEY"] = str(req["api_key"])
    if req.get("base_url"):
        env["VULNCLAW_LLM_BASE_URL"] = str(req["base_url"])
    if req.get("model"):
        env["VULNCLAW_LLM_MODEL"] = str(req["model"])
    if req.get("provider"):
        env["VULNCLAW_LLM_PROVIDER"] = str(req["provider"])
    return env


def _find_latest_run_dir(target: str) -> Path | None:
    if not RUNS_ROOT.exists():
        return None
    slug = target.replace("https://", "").replace("http://", "").replace("/", "-")[:40]
    candidates = sorted(
        [p for p in RUNS_ROOT.iterdir() if p.is_dir() and slug[:12] in p.name],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _load_findings(run_dir: Path) -> list[dict[str, Any]]:
    for rel in ("findings/findings.json", "report/findings/findings.json"):
        p = run_dir / rel
        if not p.exists():
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc.get("findings"), list):
                return doc["findings"]
            if isinstance(doc.get("verified"), list):
                return doc["verified"]
            if isinstance(doc, list):
                return doc
        except Exception:
            pass
    return []


def _load_summary(run_dir: Path) -> dict[str, Any] | None:
    p = run_dir / "summary.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def run_scan(req: dict[str, Any]) -> dict[str, Any]:
    url = (req.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "missing url"}

    scan_mode = req.get("scan_mode") or "quick"
    if scan_mode not in ("quick", "standard", "deep"):
        scan_mode = "quick"

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_ROOT.mkdir(parents=True, exist_ok=True)

    env = _configure_env(req)
    if not env.get("VULNCLAW_LLM_API_KEY"):
        return {"ok": False, "error": "missing api_key — set VULNCLAW_LLM_API_KEY or pass api_key in request"}

    cmd = [
        sys.executable,
        "-m",
        "vulnclaw.cli.main",
        "run",
        url,
        "--non-interactive",
        "--scan-mode",
        scan_mode,
        "--fail-on",
        "never",
    ]
    task = req.get("command")
    if task:
        cmd.extend(["--command", str(task)])

    timeout = int(req.get("timeout_seconds") or 600)

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s", "target": url}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "target": url}

    run_dir = _find_latest_run_dir(url)
    summary = _load_summary(run_dir) if run_dir else None
    findings = _load_findings(run_dir) if run_dir else []

    exit_code = proc.returncode
    exit_meaning = {
        0: "clean",
        1: "error",
        2: "verified finding(s)",
        3: "unverified candidate(s)",
    }.get(exit_code, f"exit {exit_code}")

    # VulnClaw exits 2/3 on findings with --fail-on never still 0, but keep raw code
    ok = exit_code in (0, 2, 3) or (summary is not None)

    report_path = None
    if run_dir:
        for candidate in (run_dir / "report.md", run_dir / "reports" / "report.md"):
            if candidate.exists():
                report_path = str(candidate)
                break

    if not ok and proc.stderr:
        err_tail = proc.stderr.strip()[-2000:]
        return {
            "ok": False,
            "target": url,
            "scan_mode": scan_mode,
            "exit_code": exit_code,
            "exit_meaning": exit_meaning,
            "error": err_tail or "vulnclaw run failed",
            "stdout_tail": (proc.stdout or "")[-1500:],
        }

    return {
        "ok": True,
        "target": url,
        "scan_mode": scan_mode,
        "exit_code": exit_code,
        "exit_meaning": exit_meaning,
        "summary": summary,
        "findings": findings,
        "finding_count": len(findings),
        "report_path": report_path,
        "run_dir": str(run_dir) if run_dir else None,
        "error": None,
    }


def main() -> None:
    try:
        raw = sys.stdin.read()
        req = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        json.dump({"ok": False, "error": f"invalid stdin JSON: {exc}"}, sys.stdout)
        sys.exit(1)

    result = run_scan(req)
    json.dump(result, sys.stdout, ensure_ascii=False)
    sys.exit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
