# AGENTS.md

## Cursor Cloud specific instructions

Thugir Scanner is a security scanner for AI-built apps. It has two runnable components plus SQL migrations:

- `web/` — Next.js 14 (App Router, TypeScript). The **core product** and free-tier scan engine, dashboard, admin, and all API routes. This is the primary service to run/test.
- `worker/` — Python FastAPI service that executes paid **Deep Scans** by importing the private `thugir-node` engine.
- `supabase/` — SQL migrations + optional pattern seed (applied against a Supabase project; not needed for local dev via `DEV_MODE`).

### Running the web app (no external services needed)

Run it from `web/` with `DEV_MODE=1`, which bypasses Supabase/Upstash/Razorpay (fake auth user, scans not persisted) so the scan engine + UI work end-to-end with **no backend/credentials**:

```bash
cd web && DEV_MODE=1 npm run dev   # http://localhost:3000
```

Set `DEV_TIER=free|deep|continuous` to preview tier-gated UI/blur (default `free`; `deep` unlocks all findings). Without `DEV_MODE`, the app needs real Supabase/Upstash/Razorpay credentials (see `docs/internal/environment-variables.md`).

### Lint / typecheck / build / test (from `web/`)

- **Typecheck is the real type gate:** `npm run typecheck` (`tsc --noEmit`) passes clean. Prefer this.
- **Lint is NOT configured in the repo:** there is no committed `.eslintrc*`, so `npm run lint` (`next lint`) drops into an interactive "configure ESLint" prompt and cannot run non-interactively. Generating a config (e.g. `next/core-web-vitals` + `next/typescript`) makes lint runnable but surfaces many pre-existing violations in existing code — do not treat those as regressions. Important side effect: once an ESLint config exists, `next build` runs lint and will **fail** on those pre-existing errors. The repo builds today precisely because no ESLint config is present.
- **Build:** `npm run build` succeeds (skips lint since no ESLint config).
- **Tests:** `npm run test:framework` runs a 40-case in-process harness (no server needed). `npm run test:smoke` POSTs to `/api/scan/free` and **requires the dev server already running** on `localhost:3000`.

### Deep Scan worker (`worker/`)

The worker imports the **private `thugir-node` engine**, resolved via `THUGIR_ENGINE_ROOT`, a git submodule at `engine/`, or a sibling `thugir-node/` checkout (see `worker/runner.py`). That engine is **not present in this repo**, so full Deep Scans cannot run here — the engine imports are lazy (inside scan functions), so the FastAPI server still boots and `/health` works, but a `/run` job fails at engine import time.

Boot the worker (deps installed by the update script into `worker/.venv`):

```bash
cd worker && ALLOW_UNSIGNED_JOBS=1 .venv/bin/uvicorn main:app --port 8099
```

`ALLOW_UNSIGNED_JOBS=1` lets you POST unsigned jobs in dev (otherwise QStash signature verification is required). Creating the venv needs the `python3.12-venv` system package (already present in the VM snapshot).
