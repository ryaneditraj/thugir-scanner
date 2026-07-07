# THUGIR Scanner — Automation Backlog

Hourly autonomous runs append shipped work here. Open PRs are deconflicted before each run.

## Shipped

| Date (UTC) | Area | Branch / PR | What shipped | Follow-ups |
|------------|------|-------------|--------------|------------|
| 2026-07-07 | detection | `auto/detection/public-cloud-storage-bucket` | Public S3/GCS/R2 bucket probe: extracts bucket URLs from client bundle, confirms read-only object listing without auth | Convex deploy-key secret pattern; exposed admin dashboard probe; live key validation for extracted AWS keys |
| 2026-07-07 | detection | `auto/detection/convex-open-query-probe` (PR #6) | Convex open-query probe for missing auth | Convex deploy key in client bundle |
| 2026-07-07 | detection | `auto/detection/algolia-admin-key-in-client` (PR #5) | Algolia admin API key detection | Algolia live key validation |
| 2026-07-07 | detection | `auto/detection/auth0-oauth-client-secret` (PR #4) | Auth0 OAuth client secret in client bundle | Auth0 Management API token pattern |
| 2026-07-07 | detection | open redirect probe (PR #3) | Open redirect via query parameter probe | Host allow-list reflection variant |
| 2026-07-07 | detection | infra artifacts (PR #2) | Probe exposed Terraform/AWS/actuator artifacts | Kubernetes dashboard paths |
| 2026-07-07 | detection | saas secrets (PR #1) | Mapbox/Sentry/PostHog/Shopify secret patterns | Live validation for each provider |

## Queued (not yet taken)

- Convex deploy key (`prod:` / `dev:`) exposed in client bundle
- Exposed admin dashboard paths (`/admin`, `/dashboard`) without auth challenge
- JWT `alg=none` / weak signing detection in client bundles
- Live Stripe/OpenAI key validation after regex match
- Scheduled re-scan diffing (feature)
- SARIF export (feature)
