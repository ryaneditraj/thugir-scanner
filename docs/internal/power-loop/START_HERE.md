# Power Loop — Start Here

Three Cursor automations on branch **`cursor/power-loop-9ec4`**, shipping to **`main`** every 12 hours.

| # | Automation | Cron (UTC) | Branch | Job |
|---|------------|------------|--------|-----|
| 1 | **Power Scan** | `0 * * * *` | `cursor/power-loop-9ec4` | Benchmarks + discover + scan |
| 2 | **Engine Evolve** | `30 * * * *` | `cursor/power-loop-9ec4` | Learn + improve scanner + draft PR |
| 3 | **Ship to Main** | `0 */12 * * *` | `cursor/power-loop-9ec4` | Gate checks → merge to `main` |

```
Hourly:   power-loop branch learns
Every 12h: ship-gate → merge to main (production)
```

Razorpay is **billing only** — no agent edits `web/lib/razorpay/**` or billing routes.

---

## Branch strategy

| Branch | Purpose |
|--------|---------|
| `cursor/power-loop-9ec4` | Sandbox — hourly scans + engine changes |
| `main` | Production — what Vercel deploys |

Automations 1 & 2 write to the power-loop branch. Automation 3 promotes to `main` when safe.

---

## One-time setup

### Cloud Agent environment

1. [cursor.com/dashboard](https://cursor.com/dashboard) → **Cloud Agents** → **Environments**
2. Connect GitHub (read/write on **ryaneditraj/thugir-scanner**)
3. Setup: `cd web && npm install`
4. Optional secrets: `OPENROUTER_API_KEY`, `OPENAI_API_KEY`
5. **Do not** add Razorpay secrets

### Create 3 automations

All at [cursor.com/automations/new](https://cursor.com/automations/new):

| Automation | Schedule | Repo branch | PR creation | Prompt file |
|------------|----------|-------------|-------------|-------------|
| Power Scan | `0 * * * *` | `cursor/power-loop-9ec4` | OFF | [AUTOMATION_1](./AUTOMATION_1_POWER_SCAN.md) |
| Engine Evolve | `30 * * * *` | `cursor/power-loop-9ec4` | ON | [AUTOMATION_2](./AUTOMATION_2_ENGINE_EVOLVE.md) |
| Ship to Main | `0 */12 * * *` | `cursor/power-loop-9ec4` | ON | [AUTOMATION_3](./AUTOMATION_3_SHIP_TO_MAIN.md) |

**Scheduled automations default to no repo — you must pick repo + branch on each one.**

Toggle all **ON** at [cursor.com/automations](https://cursor.com/automations).

---

## Ship gate (automation 3)

Before every merge to `main`:

```bash
node web/scripts/ship-gate.mjs
```

Blocks merge if:
- Razorpay / billing sacred zone changed
- `npm run typecheck` fails

Logs ships in `docs/internal/power-loop/ship-log.json`.

---

## Your job

| Frequency | Action |
|-----------|--------|
| Daily (optional) | Glance at Engine Evolve draft PRs |
| After ship runs | Confirm Vercel deployed `main` |
| If ship blocked | Read PR comment from Ship automation |

---

## Manual test

```bash
cd web && npm install
npm run power-scan -- --benchmarks
node web/scripts/ship-gate.mjs
```

---

## Learning quality

1. **Benchmarks first** (Juice Shop etc.) — oracle with known answers
2. **Teacher delta** (Nuclei / thugir-node) — import proven checks
3. **Discovery** — lowest priority

See `AUTOMATION_1` and `AUTOMATION_2` for details.
