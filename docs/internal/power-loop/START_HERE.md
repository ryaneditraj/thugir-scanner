# Power Loop — Start Here

Two Cursor automations that run hourly on branch **`cursor/power-loop-9ec4`**.

| Automation | Cron (UTC) | Job |
|------------|------------|-----|
| **Power Scan** | `0 * * * *` | Benchmarks + discover sites + scan locally |
| **Engine Evolve** | `30 * * * *` | Learn from oracle gaps + open draft PR |

Razorpay is **billing only** — agents never edit `web/lib/razorpay/**` or billing routes.

---

## Step 1 — Cloud Agent environment (one time)

1. Open [cursor.com/dashboard](https://cursor.com/dashboard) → **Cloud Agents** → **Environments**
2. Connect **GitHub** (read/write on this repo)
3. Create environment **Thugir Power**:
   - Repository: this repo
   - Install: `cd web && npm install`
   - Optional: `cd worker && pip install -r requirements.txt` (for thugir-node teacher scans)
4. **Secrets** (optional but recommended):
   - `OPENROUTER_API_KEY` or `OPENAI_API_KEY` — enables AI deep probe layer

Do **not** add Razorpay secrets to the evolution environment.

---

## Step 2 — Branch is ready

This branch includes:

```
docs/internal/power-loop/     ← handoff JSON (results, queue, scoreboard)
web/scripts/power-scan.ts      ← local max scan (no production API)
```

Push is required before automations can use it:

```bash
git push -u origin cursor/power-loop-9ec4
```

---

## Step 3 — Create Automation 1: Power Scan

1. Go to [cursor.com/automations/new](https://cursor.com/automations/new)
2. **Name:** `Thugir — Power Scan`
3. **Trigger:** Scheduled → Custom cron → `0 * * * *`
4. **Repository:** this repo
5. **Branch:** `cursor/power-loop-9ec4` ← required for scheduled runs
6. **Computer use:** ON
7. **Pull request creation:** OFF
8. **Prompt:** copy from [AUTOMATION_1_POWER_SCAN.md](./AUTOMATION_1_POWER_SCAN.md)
9. Save → toggle **ON**

---

## Step 4 — Create Automation 2: Engine Evolve

1. [cursor.com/automations/new](https://cursor.com/automations/new)
2. **Name:** `Thugir — Engine Evolve`
3. **Trigger:** Scheduled → `30 * * * *`
4. **Repository:** this repo
5. **Branch:** `cursor/power-loop-9ec4`
6. **Pull request creation:** ON
7. **Prompt:** copy from [AUTOMATION_2_ENGINE_EVOLVE.md](./AUTOMATION_2_ENGINE_EVOLVE.md)
8. Save → toggle **ON**

---

## Step 5 — Verify first run

After the top of the hour:

1. Check branch `cursor/power-loop-9ec4` on GitHub
2. `docs/internal/power-loop/results.json` should have new entries
3. `scoreboard.json` should update
4. After `:30`, look for a **draft PR** to `main`

---

## Step 6 — Your daily job (~5 min)

1. [cursor.com/automations](https://cursor.com/automations) — both toggles ON
2. Review draft PR from Engine Evolve
3. Merge if benchmark recall improved

---

## Manual test (optional)

```bash
cd web && npm install
cd web && npx tsx scripts/power-scan.ts --benchmarks
cat docs/internal/power-loop/results.json
```

---

## How learning stays high quality

Power Scan runs **benchmarks first** (known-vulnerable apps). Engine Evolve prioritizes:

1. Benchmark misses (proven vulns you didn't catch)
2. Teacher delta (Nuclei / thugir-node found, you didn't)
3. Discovery on unknown sites (lowest priority)

See conversation history in repo docs for full oracle architecture.
