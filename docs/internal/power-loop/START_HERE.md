# Power Loop — Start Here

**Four automations** — hourly learning, PR hygiene, 12h ship to production.

| # | Automation | Cron (UTC) | Branch | Job |
|---|------------|------------|--------|-----|
| 1 | **Power Scan** | `0 * * * *` | `cursor/power-loop-9ec4` | Benchmarks + discover + scan |
| 2 | **Engine Evolve** | `30 * * * *` | `cursor/power-loop-9ec4` | Improve scanner (commit only, no PR spam) |
| 3 | **PR Triage** | `45 * * * *` | **`main`** | Dedupe ~25 open PRs, sync backlog, close shells |
| 4 | **Ship to Main** | `0 */12 * * *` | `cursor/power-loop-9ec4` | Gate → merge power-loop + batch detection PRs |

```
:00 Power Scan      → power-loop branch learns
:30 Engine Evolve   → commits to power-loop (no new PR each hour)
:45 PR Triage       → cleans open PR backlog on main
:00 every 12h Ship  → main = production
```

---

## Many pending PRs?

You already have ~25 open PRs from detection automations. **PR Triage** + `manage-pr-integrity.mjs` handles this:

```bash
cd web && node scripts/manage-pr-integrity.mjs --audit
```

See `docs/AUTOMATION_BACKLOG.md` — single source of truth for what's open.

**Typical cleanup:** close retired shells `#11, #14, #16, #17, #18, #19, #21` (branches already deleted).

---

## Create automations

[cursor.com/automations/new](https://cursor.com/automations/new)

| Automation | Branch | Prompt |
|------------|--------|--------|
| Power Scan | `cursor/power-loop-9ec4` | [AUTOMATION_1](./AUTOMATION_1_POWER_SCAN.md) |
| Engine Evolve | `cursor/power-loop-9ec4` | [AUTOMATION_2](./AUTOMATION_2_ENGINE_EVOLVE.md) |
| PR Triage | **`main`** | [AUTOMATION_4](./AUTOMATION_4_PR_TRIAGE.md) |
| Ship to Main | `cursor/power-loop-9ec4` | [AUTOMATION_3](./AUTOMATION_3_SHIP_TO_MAIN.md) |

Toggle all ON at [cursor.com/automations](https://cursor.com/automations).

---

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run power-scan -- --benchmarks` | Local max scan |
| `npm run ship-gate` | Block merge if billing touched / typecheck fails |
| `npm run pr-integrity` | Audit open PR collisions |

---

## Sacred zone (never auto-merge if changed)

`web/lib/razorpay/**`, billing routes, webhooks, `UpgradePanel.tsx`

---

## Your job

| When | Action |
|------|--------|
| Once | Merge PR #25 (brings `manage-pr-integrity.mjs` to main) if not already there |
| Daily | Glance at Ship automation merges |
| If PR count grows | Check PR Triage ran at :45 |
