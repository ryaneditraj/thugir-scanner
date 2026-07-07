# Automation Backlog

Hourly autonomous runs log shipped work here. Open PRs and `done` entries are deconflicted before each run.

## Open PRs (do not duplicate)

| PR | Area | Title | Branch |
|----|------|-------|--------|
| #1 | detection | Mapbox, Sentry, PostHog, Shopify secret patterns | `cursor/thugir-scanner-evolution-d94f` |
| #2 | detection | Probe exposed infra artifacts (Terraform, AWS, actuator) | `cursor/thugir-scanner-evolution-9233` |
| #3 | detection | Open redirect via query parameter probe | `cursor/thugir-scanner-evolution-d346` |
| #4 | detection | Auth0 OAuth client secret in client bundle | `cursor/thugir-scanner-evolution-9475` |

## Done

| Date (UTC) | Area | Shipped | Follow-ups |
|------------|------|---------|------------|
| 2026-07-07 | detection | **Algolia admin API key in client bundle** — `algoliaAdminKeyInClient` rule_ref + `vibe-algolia-admin-in-client` pattern. Flags `ALGOLIA_ADMIN_API_KEY` / `adminApiKey` with hex validation; ignores search-only keys. Branch: `auto/detection/algolia-admin-key-in-client`. | Public S3/GCS/R2 bucket URL probes; Convex open deployment probe; exposed admin dashboard HTTP probes; MongoDB Atlas connection string in bundle; live Algolia admin-key ACL validation (rate-limited). |

## Queued (not yet taken)

- **detection** — Public S3/GCS/R2 bucket URLs in bundle + anonymous HEAD/ListBucket proof.
- **detection** — Convex open deployment probe (fingerprint exists in `detect/index.ts`, no patterns yet).
- **detection** — Exposed admin dashboard HTTP probes (`/admin`, `/dashboard` without auth redirect).
- **detection** — MongoDB / Atlas connection string in client bundle (`secret_regex` + inline state parity).
- **detection** — JWT alg=none runtime probe (codescan rule exists; not in free HTTP scan).
- **feature** — Wire admin `patterns` DB table into `runFreeScan` runtime merge.
- **feature** — Scheduled re-scans with finding diff ("what changed since last scan").
- **frontend** — Evidence viewer polish + copy-fix-prompt buttons on scan results.
