# Deep Scan Worker

Python FastAPI service that executes Deep Scans by reusing the `thugir-node` engine modules.
It runs **outside Vercel** (Render / Fly.io) because the engine shells out to `nmap` / `nikto`
/ `nuclei` and scans can run for minutes.

## Why it is separate

- The free-tier checks run inside the Next.js app (Vercel). They are single-request and cheap.
- Deep Scan reuses Python engine code and external CLI tools, which cannot run in a Vercel
  function. QStash bridges the two: the app enqueues a job, QStash POSTs it here.

## Flow

1. `POST /api/scan/deep` (Next.js) verifies entitlement + domain ownership, creates a `queued`
   scan row, and publishes a job to QStash.
2. QStash POSTs the signed job to `POST /run` here.
3. We verify the signature, set the scan `running`, run `runner.run_deep_scan` (capped), write
   findings to Supabase, and set the scan `done`.
4. Admin "kill" sets `status='killed'`; the runner checks this cooperatively and aborts.

## Local dev

```bash
cd worker
python3 -m venv .venv
.venv/bin/pip install -r ../../thugir-node/requirements.txt -r ../../thugir-node/requirements-api.txt -r requirements.txt
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

- `DEEP_MAX_RUNTIME_S` (default 240) - hard wall-clock cap.
- `DEEP_API_MAX_ENDPOINTS` (default 120) - API engine endpoint cap.
- `DEEP_RUN_EXTERNAL_TOOLS` / `DEEP_RUN_NUCLEI` - enable only where the binaries exist.

## Deployment note

Render's free tier spins down (cold start ~50s) - fine for testing, but for a paid product
where a buyer is waiting, run the smallest always-on paid instance (Render Starter / Fly.io).
