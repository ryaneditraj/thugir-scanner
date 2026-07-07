# Automation backlog

Hourly autonomous runs ship one PR each. Entries are append-only.

## Shipped

| Date (UTC) | Area | Branch | What shipped | Follow-ups |
|------------|------|--------|--------------|------------|
| 2026-07-07 | detection | `auto/detection/ssti-canary-probe` | SSTI canary probe: injects harmless template math (`{{17359*28471}}`, `${…}`, `<%= … %>`) into common query params; fires only when the unique product `494163289` appears without the raw payload (evaluation proof). Pattern `ssti-query-parameter`, rule `sstiCanary`. | Live Twilio key validation; CSRF on state-changing routes; stored XSS via POST body canary |

## Open PRs (do not duplicate)

Tracked via `gh pr list` — includes reflected XSS, open redirect, JWT alg=none, admin panel, cloud buckets, Convex probes, Algolia/Auth0 secrets, Twilio pairing, infra artifacts, Mapbox/Sentry/PostHog/Shopify patterns, PR integrity audits.

## Queued (high impact)

1. **detection** — Live Twilio API key validation (pair SID + auth token, harmless GET)
2. **detection** — CSRF probe on state-changing routes discovered from bundle
3. **detection** — Client-bundle internal URL / feature-flag extraction
4. **feature** — Scheduled re-scans with diff ("what changed since last scan")
5. **frontend** — Evidence viewer copy-fix-prompt + severity filters on results
