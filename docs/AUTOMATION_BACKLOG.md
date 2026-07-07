# Automation backlog

Hourly autonomous runs ship one PR each. Entries are append-only.

## Shipped

| Date (UTC) | Area | Branch | What shipped | Follow-ups |
|------------|------|--------|--------------|------------|
| 2026-07-07 | detection | `auto/detection/twilio-live-key-validation` | Live Twilio credential validation: pairs accountSid + 32-char auth token from the client bundle, then confirms with a harmless `GET /2010-04-01/Accounts/{Sid}.json` (fires only on HTTP 200 with matching sid). Replaces loose SID-only regex with rule `twilioLiveCredentialProbe`. | CSRF on state-changing routes; Stripe/OpenAI live-key validation; client-bundle internal URL extraction |

## Open PRs (do not duplicate)

Tracked via `gh pr list` — includes reflected XSS, SSTI, open redirect, JWT alg=none, admin panel, cloud buckets, Convex probes, Algolia/Auth0 secrets, Twilio pairing (static), infra artifacts, Mapbox/Sentry/PostHog/Shopify patterns, PR integrity audits.

## Queued (high impact)

1. **detection** — CSRF probe on state-changing routes discovered from bundle
2. **detection** — Live Stripe / OpenAI key validation (harmless provider read)
3. **detection** — Client-bundle internal URL / feature-flag extraction
4. **feature** — Scheduled re-scans with diff ("what changed since last scan")
5. **frontend** — Evidence viewer copy-fix-prompt + severity filters on results
