# Automation Backlog

Hourly autonomous runs log shipped work here. Open PRs and `done` entries are deconflicted before each run.

## Done

| Date (UTC) | Area | Shipped | Follow-ups |
|------------|------|---------|------------|
| 2026-07-07 | detection | **PR #1:** Added 4 high-precision `secret_regex` providers: Mapbox secret token (`sk.eyJ…`), Sentry auth token (`sntrys_…`), PostHog personal API key (`phx_…`), Shopify Admin API token (`shpat_…`). Includes max-damage copy + regex regression tests. Branch: `cursor/thugir-scanner-evolution-d94f`. | Algolia admin-key detection (contextual rule_ref); Auth0/Datadog/npm tokens; S3/GCS public bucket HEAD probes; Convex deployment auth probe; wire DB `patterns` table into runtime merge; active Stripe webhook signature probe (deep tier). |

## Queued (not yet taken)

- **detection** — Algolia admin API key via `rule_ref` (context: `algoliasearch` + `adminApiKey` assignment; avoid search-only `phc_`/`NEXT_PUBLIC_` keys).
- **detection** — Public S3/GCS/R2 bucket URLs in bundle + anonymous HEAD/ListBucket proof.
- **detection** — Convex open deployment probe (fingerprinted but never checked).
- **detection** — Exposed admin dashboard HTTP probes (`/admin`, `/dashboard`, session JSON leaks).
- **detection** — Auth0 client secret / management token patterns.
- **feature** — Wire admin `patterns` DB table into `runFreeScan` runtime merge.
- **feature** — Scheduled re-scans with finding diff ("what changed since last scan").
- **frontend** — Evidence viewer polish + copy-fix-prompt buttons on scan results.
