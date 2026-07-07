# Automation backlog

Hourly autonomous runs log shipped work here. Open PRs are checked before each run to avoid duplicates.

## Shipped

| Date (UTC) | Area | PR / branch | What shipped | Follow-ups |
|------------|------|-------------|--------------|------------|
| 2026-07-07 | detection | `auto/detection/exposed-admin-dashboard` | Exposed admin panel probe: GETs `/admin`, `/dashboard`, `/manage` and flags when admin UI HTML is returned without login redirect | JWT alg=none active probe; Convex deploy-key secret pattern; admin path discovery from bundle |
| 2026-07-07 | detection | `auto/detection/convex-open-query-probe` | Convex open-query probe: extracts deployment URL from bundle, POSTs harmless read-only `/api/query` calls, flags queries returning real rows without auth | Convex deploy-key secret pattern; mutation reachability (deep tier); S3/GCS/R2 bucket probes |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-afe6` | Algolia admin API key in client bundle | — |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-9475` | Auth0 OAuth client secret in client bundle | — |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-d346` | Open redirect via query parameter probe | — |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-9233` | Exposed infra artifacts (Terraform, AWS, actuator) | — |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-d94f` | Mapbox, Sentry, PostHog, Shopify secret patterns | — |

## Queued (not yet taken)

- Convex deploy/admin key leak in client bundle (`secret_regex`)
- JWT alg=none acceptance probe (active HTTP, deep tier)
- Scheduled re-scan diffing (feature)
- SARIF export (feature)
