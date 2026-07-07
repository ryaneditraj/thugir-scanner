# THUGIR Scanner — Automation Backlog

Hourly autonomous runs pick the highest-impact item **not** already in an open PR or marked done below.

## Shipped

| Date (UTC) | Area | Branch / PR | What shipped | Follow-ups |
|------------|------|-------------|--------------|------------|
| 2026-07-07 17:01 | detection | `auto/detection/stripe-live-key-validation` | Live Stripe `sk_live_*` validation via Balance API; pattern upgraded from regex-only to `rule_ref` with evidence-gated proof | OpenAI live-key validation; CSRF state-changing probe; Stripe restricted-key (`rk_live_*`) live validation |
| 2026-07-07 16:00 | detection | `auto/detection/twilio-live-key-validation` | Live Twilio credential validation via Accounts API | — |
| 2026-07-07 15:00 | detection | `auto/detection/ssti-canary-probe` | SSTI canary probe via query parameters | — |
| 2026-07-07 14:01 | detection | `auto/detection/reflected-xss-probe` | Reflected XSS canary probe via query parameters | — |
| 2026-07-07 13:01 | detection | `auto/detection/twilio-auth-token-pairing` | Twilio auth token pairing replaces loose SID regex | Superseded by live validation PR |
| 2026-07-07 12:01 | detection | `auto/detection/convex-deploy-key-secret` | Convex deploy key secret in client bundle | — |
| 2026-07-07 11:01 | detection | `auto/detection/jwt-alg-none-probe` | JWT alg=none acceptance probe | — |
| 2026-07-07 10:02 | detection | `auto/detection/exposed-admin-dashboard` | Exposed admin panel probe | — |
| 2026-07-07 09:01 | detection | `auto/detection/public-cloud-storage-bucket` | Public S3/GCS/R2 bucket probe | — |
| 2026-07-07 08:00 | detection | `auto/detection/convex-open-query-probe` | Convex open-query probe | — |
| 2026-07-07 07:01 | detection | `auto/detection/algolia-admin-key-in-client` | Algolia admin API key detection | — |
| 2026-07-07 06:01 | detection | `auto/detection/auth0-oauth-client-secret` | Auth0 OAuth client secret detection | — |
| 2026-07-07 05:02 | detection | `cursor/thugir-scanner-evolution-d346` | Open redirect via query parameter probe | — |
| 2026-07-07 04:05 | detection | `cursor/thugir-scanner-evolution-9233` | Exposed infra artifacts probe | — |
| 2026-07-07 03:05 | detection | `cursor/thugir-scanner-evolution-d94f` | Mapbox, Sentry, PostHog, Shopify secret patterns | — |

## Queued (not yet taken)

- **detection**: OpenAI live-key validation (`/v1/models` read)
- **detection**: CSRF probe on state-changing routes (missing token / SameSite bypass)
- **detection**: Stripe restricted key (`rk_live_*`) live validation
- **detection**: Anthropic live-key validation
- **feature**: Scheduled re-scans + diffing
- **frontend**: Evidence viewer polish + copy-fix-prompt buttons

## Open PR deconflict notes

Do **not** duplicate: Twilio live validation (#17), SSTI (#15), XSS (#13), open redirect (#3), admin panel (#8), JWT alg=none (#9), Convex (#6, #10), cloud storage (#7), Algolia (#5), Auth0 (#4), infra artifacts (#2), Mapbox/Sentry/PostHog (#1).
