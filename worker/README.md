# Deep Scan Worker

Python FastAPI service that executes Deep Scans by embedding **TCSF**
(Thugir Cognitive Security Framework) from `thugir-node`. It runs **outside
Vercel** (Render / Fly.io) because the engine shells out to `nmap` / `nikto` /
`nuclei` and scans can run for minutes.

## Why it is separate

- The free-tier checks run inside the Next.js app (Vercel). They are single-request and cheap.
- Deep Scan reuses Python TCSF + Nexus modules and external CLI tools, which cannot run in a
  Vercel function. QStash bridges the two: the app enqueues a job, QStash POSTs it here.

## Flow

1. `POST /api/scan/deep` (Next.js) verifies entitlement + domain ownership, creates a `queued`
   scan row, and publishes a job to QStash.
2. QStash POSTs the signed job to `POST /run` here.
3. We verify the signature, set the scan `running`, run `runner.run_deep_scan` (capped), write
   findings to Supabase, and set the scan `done`.
4. Admin "kill" sets `status='killed'`; the runner checks this cooperatively and aborts.

## Engine (TCSF)

Point at a `thugir-node` tree that contains `tcsf/` (from [thugirlabs.com](https://github.com/ryaneditraj/thugirlabs.com)):

```bash
# From repo root — sparse-checkouts thugir-node → ./engine
./scripts/sync-engine.sh            # tip of main
./scripts/sync-engine.sh <ref>      # branch / tag / sha
```

Or set `THUGIR_ENGINE_ROOT` to an existing checkout (e.g. `~/THUGIR LABS/thugir-node`).

The runner auto-detects `./engine`, then sibling Labs paths, then the env override.

**Commercial policy (defaults):**

| Env | Default | Meaning |
|-----|---------|---------|
| `DEEP_USE_MAX_POWER` | `1` | Aggressive max-power / runtime path |
| `DEEP_USE_TCSF_RUNTIME` | `1` | Prefer portable `TcsfRuntime` when available |
| `TCSF_PRECISION_MODE` | `1` | High/Critical require exploit proof |
| `TCSF_POWER_ROUNDS` | `8` | Cap vs research-platform 15–20 |
| `TCSF_SKIP_M365` / `TCSF_SKIP_CLOUD` | `1` | Skip enterprise surfaces (vibe-app ICP) |
| `TCSF_PRODUCT_ID` | `thugir-scanner` | Audit tag on findings |

Findings are enriched with **evidence verdicts** (`confirmed` / `likely` / `inconclusive` /
`not_exploitable`) via `tcsf.evidence.verdict` and stored on `engine_status` + `evidence_json`.

## Local dev

```bash
# one-time: pull TCSF engine
./scripts/sync-engine.sh

cd worker
python3 -m venv .venv
.venv/bin/pip install -r ../engine/requirements.txt -r requirements.txt
cp .env.example .env   # fill in Supabase + QStash keys
set -a && source .env && set +a
ALLOW_UNSIGNED_JOBS=1 .venv/bin/uvicorn main:app --port 8099 --reload
```

Then enqueue a test job (unsigned, dev only):

```bash
curl -X POST localhost:8099/run -H 'Content-Type: application/json' \
  -d '{"scanId":"<uuid>","userId":"<uuid>","targetUrl":"https://example.com","includeInjection":true}'
```

## Caps (env)

- `DEEP_MAX_RUNTIME_S` (default 420) — hard wall-clock cap.
- `DEEP_API_MAX_ENDPOINTS` (default 400) — API engine endpoint cap.
- `DEEP_RUN_EXTERNAL_TOOLS` / `DEEP_RUN_NUCLEI` — enable only where the binaries exist.

## Deployment note

Render's free tier spins down (cold start ~50s) — fine for testing, but for a paid product
where a buyer is waiting, run the smallest always-on paid instance (Render Starter / Fly.io).
Set `THUGIR_ENGINE_ROOT` to the synced `engine/` path in the container image.
