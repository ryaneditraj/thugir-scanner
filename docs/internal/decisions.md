# Build decisions (defaults applied)

The plan left four decisions open and said to apply defaults if unanswered. These are the
defaults this build ships with. Change any of them and tell the engineer.

## 1. Ownership verification - DECIDED: tiered
- Free scan: click-through attestation + Upstash rate-limiting + SSRF guard (refuses private
  hosts). Implemented in [api/scan/free](../../web/app/api/scan/free/route.ts) +
  [lib/checks/http.ts](../../web/lib/checks/http.ts).
- Deep / Continuous: proof of domain control required - well-known file, meta tag, or DNS TXT.
  Implemented in [lib/ownership](../../web/lib/ownership/index.ts) +
  [api/ownership/verify](../../web/app/api/ownership/verify/route.ts).

## 2. Worker host - DECIDED for dev: Render free; for launch: small always-on instance
- The worker spins down on Render free (cold start ~50s) which is fine for testing but not for a
  paying buyer waiting on a scan. Move to Render Starter or Fly.io before charging.
- Everything else stays free: Vercel Hobby + Supabase free + Upstash free.

## 3. Razorpay amounts - PLACEHOLDER
- `DEEP_SCAN_AMOUNT_INR` and `RAZORPAY_CONTINUOUS_PLAN_ID` are read from env and currently unset.
  Set them when pricing is decided. No code change needed.

## 4. InjectionSpecialist in Deep Scan v1 - DECIDED: included, guarded, verified-only
- Deep Scans only run on verified domains, so `includeInjection=true` is passed.
- The standalone `InjectionSpecialist` call is best-effort/guarded in
  [worker/runner.py](../../worker/runner.py) (synthetic TaskNode); if it cannot be constructed it
  is skipped. The API engine's BOLA/IDOR/JWT probes (`scan_api`) provide the primary injection-
  class coverage regardless.

## 5. Razorpay subscription signature — FIXED
- Razorpay signs subscription checkout success as `HMAC(payment_id | subscription_id)`, which is
  the **opposite** field order from one-time orders (`HMAC(order_id | payment_id)`). The verify
  route previously reused the order verifier for subscriptions, so every Continuous Protection
  checkout failed verification. Now `verifySubscriptionSignature` handles subscriptions and the
  client sends `orderId`/`subscriptionId` as distinct fields. See the "Billing & entitlements"
  section in [architecture.md](architecture.md).
- Webhook `payment.captured` can arrive with empty `notes` (order notes are not copied to the
  payment entity); it now falls back to `orders.fetch(order_id)` to recover `user_id`/`kind`.

## Note on the legacy `engine.scan(url, mode)` reference
CLAUDE.md mentions `engine.scan(url, mode)` with modes `quick/full/network`. That describes the
archived `archive/nexus_core/` API, not live `thugir-node`. The live engine entry is
`NexusEngine.run()` (heavy) or the standalone `modules/*` functions we actually call. We use the
standalone functions, not `NexusEngine`.
