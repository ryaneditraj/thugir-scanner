# Automation Backlog

Hourly autonomous runs ship one focused PR each. This file deconflicts across runs.

## Shipped

| Date (UTC) | Area | Branch | What shipped | Follow-ups |
|------------|------|--------|--------------|------------|
| 2026-07-07 | detection | `auto/detection/jwt-alg-none-probe` | Active JWT `alg:none` acceptance probe (`jwtAlgNoneProbe` rule + `jwt-alg-none-accepted` pattern, deep tier) | Convex deploy key secret regex; Twilio auth token pairing; open redirect probe |
| 2026-07-07 | detection | `auto/detection/exposed-admin-dashboard` | Exposed admin panel probe without authentication | — |
| 2026-07-07 | detection | `auto/detection/public-cloud-storage-bucket` | Public S3/GCS/R2 bucket probe from client bundle URLs | — |
| 2026-07-07 | detection | `auto/detection/convex-open-query-probe` | Convex open-query probe for missing auth | Convex deploy key secret regex |
| 2026-07-07 | detection | `auto/detection/algolia-admin-key-in-client` | Algolia admin API key in client bundle | — |
| 2026-07-07 | detection | `auto/detection/auth0-oauth-client-secret` | Auth0 OAuth client secret in client bundle | — |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-d346` | Open redirect via query parameter probe | — |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-9233` | Probe exposed infra artifacts (Terraform, AWS, actuator) | — |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-d94f` | Mapbox, Sentry, PostHog, Shopify secret patterns | — |

## Open PRs (do not duplicate)

- #1 Mapbox/Sentry/PostHog/Shopify secret patterns
- #2 Exposed infra artifacts probe
- #3 Open redirect query parameter probe
- #4 Auth0 OAuth client secret
- #5 Algolia admin API key
- #6 Convex open-query probe
- #7 Public S3/GCS/R2 bucket probe
- #8 Exposed admin panel probe

## Queued (highest impact next)

1. **Convex deploy key secret** — `secret_regex` for `dev:\|…\|eyJ` / `prod:…` deploy keys in client bundles
2. **Twilio auth token** — pair Account SID with auth token regex (currently SID-only)
3. **Open redirect** — may be covered by PR #3; verify before implementing
4. **PlanetScale / Upstash / Mongo URI** — extend `stack-database-url-in-bundle` family
5. **Vercel/Netlify deploy tokens** — CI leak patterns
