# Power Loop — Start Here

**Four automations** on branch **`main`** (production).

| # | Automation | Cron (UTC) | Job |
|---|------------|------------|-----|
| 1 | **Power Scan** | `0 * * * *` | Benchmarks + discover + scan |
| 2 | **Engine Evolve** | `30 * * * *` | Improve scanner (commit to main) |
| 3 | **PR Triage** | `45 * * * *` | Dedupe open PRs, sync backlog |
| 4 | **Ship to Main** | `0 */12 * * *` | Gate checks (main already = prod) |

```
:00 Power Scan      → scan + learn
:30 Engine Evolve   → improve detection engine
:45 PR Triage       → clean PR backlog
:00 every 12h Ship  → validate + log (main is production)
```

---

## Security skills library (141 playbooks)

```
docs/internal/security-skills/
├── index.json              ← searchable catalog
├── skills/WEB/OWASP_WSTG_4.2/   ← 125 WSTG tests
└── skills/attack-*/        ← 16 attack playbooks
```

Loader: `web/lib/methodology/skills.ts`  
Methodology: `web/lib/methodology/` (3-gate, severity triage, coverage)

**Agent engine (VulnClaw):** `services/vulnclaw/` — full AI pentest agent. See `docs/internal/vulnclaw-integration.md`.

---

## Create automations

[cursor.com/automations/new](https://cursor.com/automations/new)

| Automation | Branch | Prompt file |
|------------|--------|-------------|
| Power Scan | **`main`** | [AUTOMATION_1](./AUTOMATION_1_POWER_SCAN.md) |
| Engine Evolve | **`main`** | [AUTOMATION_2](./AUTOMATION_2_ENGINE_EVOLVE.md) |
| PR Triage | **`main`** | [AUTOMATION_4](./AUTOMATION_4_PR_TRIAGE.md) |
| Ship to Main | **`main`** | [AUTOMATION_3](./AUTOMATION_3_SHIP_TO_MAIN.md) |

**Important:** Scheduled automations default to no repo — you must pick **repo + branch `main`** on each one.

Toggle all ON at [cursor.com/automations](https://cursor.com/automations).

---

## Scripts

```bash
cd web && npm run power-scan -- --benchmarks
cd web && npm run ship-gate
cd web && npm run pr-integrity
node docs/internal/security-skills/build-index.mjs
```

---

## Sacred zone (never auto-merge if changed)

`web/lib/razorpay/**`, billing routes, webhooks, `UpgradePanel.tsx`

---

## PR backlog cleanup (manual — one time)

Open PRs with **deleted branches** must be closed on GitHub UI (automations cannot close PRs):

Close orphaned PR shells on GitHub UI (automations cannot close PRs):

```bash
cd web && npm run close-orphan-prs -- --close
```

Or close manually: **#1–#26** plus integrity shells **#11, #14, #16–#21, #25**

Then run: `cd web && node scripts/manage-pr-integrity.mjs --audit`

See `docs/AUTOMATION_BACKLOG.md` for current truth.

---

## Your job

| When | Action |
|------|--------|
| Once | Close orphaned PR shells on GitHub (list above) |
| Daily | Glance at automation commits on `main` |
| Weekly | Check Vercel deployed latest `main` |
