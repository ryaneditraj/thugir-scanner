# Environment variables reference

## Web app (Vercel) - `web/.env.local`

Client-exposed (safe):
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_RAZORPAY_KEY_ID`
- `NEXT_PUBLIC_SITE_URL`

Server-only (never exposed to client):
- `SUPABASE_SERVICE_ROLE_KEY` - bypasses RLS; used by route handlers + admin actions.
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` - rate limiting.
- `QSTASH_TOKEN` - publish Deep Scan jobs.
- `WORKER_URL` - public URL of the Python worker `/run`.
- `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`.
- `WORKER_CALLBACK_SECRET` - shared secret; also used to derive ownership tokens (HMAC).
- `CRON_SECRET` - Vercel Cron auth for `/api/cron/monitors`.
- `RESEND_API_KEY`, `RESEND_FROM` - optional monitor delta emails.
- `DEEP_SCAN_AMOUNT_INR`, `RAZORPAY_CONTINUOUS_PLAN_ID` - pricing (set at launch).
- `THUGIR_AGENT_SCAN_ENABLED` - enable agent engine on worker (`1`).
- `THUGIR_AGENT_LLM_API_KEY` - LLM key for Thugir Agent Engine.
- `THUGIR_AGENT_PYTHON` - path to Python binary for agent engine.

## Worker (Render/Fly) - `worker/.env`
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`
- `QSTASH_CURRENT_SIGNING_KEY`, `QSTASH_NEXT_SIGNING_KEY` - verify job signatures.
- `SITE_URL` or `NEXT_PUBLIC_SITE_URL` - callback target for monitor delta emails.
- `WORKER_CALLBACK_SECRET` - must match the web app secret.
- `ALLOW_UNSIGNED_JOBS` - dev only; never set in prod.
- `DEEP_MAX_RUNTIME_S`, `DEEP_API_MAX_ENDPOINTS`, `DEEP_WEB_TIMEOUT_S`
- `DEEP_RUN_EXTERNAL_TOOLS`, `DEEP_RUN_NUCLEI` - enable only where binaries exist.
- `OPENROUTER_API_KEY` - optional; engine degrades to heuristics without it.

## Deployment process (summary)
1. Push `web/` to Vercel; set all server env vars in the Vercel project (Production + Preview).
2. Deploy `worker/` to Render/Fly with its env; set `WORKER_URL` in Vercel to its `/run` URL.
3. Configure the Razorpay webhook to `https://<site>/api/webhooks/razorpay` with the same secret.
4. Configure QStash to allow publishing to `WORKER_URL`.
