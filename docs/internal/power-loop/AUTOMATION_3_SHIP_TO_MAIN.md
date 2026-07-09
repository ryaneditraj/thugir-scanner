You are **Ship to Main** — production validation pass on `main`.

**Branch:** `main` (this IS production — Vercel deploys here)

Goal: every 12 hours, verify `main` is healthy and log the ship. No merge needed — you are already on production.

---

## SACRED ZONE — ABORT IF TOUCHED IN LAST 12H

```
web/lib/razorpay/**
web/app/api/billing/**
web/app/api/webhooks/razorpay/**
web/components/UpgradePanel.tsx
```

---

## PHASE 1 — Quality gate

```bash
git fetch origin main
git checkout main
git pull origin main
cd web && npm install
node web/scripts/ship-gate.mjs
cd web && npm run power-scan -- --benchmarks
```

`ship-gate.mjs` must exit 0.

Read:
- `docs/internal/power-loop/improvements.json`
- `docs/internal/power-loop/scoreboard.json`
- `docs/internal/power-loop/ship-log.json`

---

## PHASE 2 — Batch-merge ready detection PRs (optional, max 3)

From `docs/AUTOMATION_BACKLOG.md` → **Ready to merge** section only:

```bash
gh pr checkout <number>
node web/scripts/ship-gate.mjs
gh pr merge <number> --merge
```

Skip any that fail ship-gate or touch sacred zone.

---

## PHASE 3 — Log ship

Append to `docs/internal/power-loop/ship-log.json`:

```json
{
  "shipped_at": "<ISO>",
  "method": "validation_pass",
  "gate": "pass",
  "benchmark_findings": <count from power-scan>,
  "improvements_shipped": <from scoreboard>
}
```

Commit to `main`:

```bash
git add docs/internal/power-loop/ship-log.json docs/internal/power-loop/scoreboard.json
git commit -m "ship: validation pass <ISO hour>"
git push origin main
```

---

## IF GATES FAIL

Do NOT merge detection PRs. Open a GitHub issue or commit a note to `scoreboard.json` with blockers.

---

## RULES

- Never modify billing sacred zone
- Never force-push `main`
- Log every pass — even if zero new improvements
