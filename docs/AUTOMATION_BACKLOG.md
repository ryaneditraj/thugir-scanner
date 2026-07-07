# Automation backlog

Hourly autonomous runs log shipped work here. Open PRs are checked before each run to avoid duplicates.

## Shipped

| Date (UTC) | Area | Branch / PR | What shipped | Follow-ups |
|------------|------|-------------|--------------|------------|
| 2026-07-07 13:01 | detection | `auto/detection/twilio-auth-token-pairing` | Twilio auth token pairing — replaced loose `AC…` SID regex with `twilioCredentialsInClient` rule requiring auth token + SID proximity or `TWILIO_AUTH_TOKEN` in bundle | Reflected XSS canary probe; live Twilio key validation via harmless Accounts API read |
| 2026-07-07 12:01 | detection | `auto/detection/convex-deploy-key-secret` | Convex deploy key secret in client bundle | — |
| 2026-07-07 11:01 | detection | `auto/detection/jwt-alg-none-probe` | JWT alg=none acceptance probe | — |
| 2026-07-07 10:02 | detection | `auto/detection/exposed-admin-dashboard` | Exposed admin panel probe | — |
| 2026-07-07 09:01 | detection | `auto/detection/public-cloud-storage-bucket` | Public S3/GCS/R2 bucket probe | — |
| 2026-07-07 08:00 | detection | `auto/detection/convex-open-query-probe` | Convex open-query probe | — |
| 2026-07-07 07:01 | detection | `auto/detection/algolia-admin-key-in-client` | Algolia admin API key in client bundle | — |
| 2026-07-07 06:01 | detection | `auto/detection/auth0-oauth-client-secret` | Auth0 OAuth client secret detection | — |
| 2026-07-07 05:02 | detection | open redirect probe | Open redirect via query parameter | — |
| 2026-07-07 04:05 | detection | infra artifact probes | Exposed Terraform/AWS/actuator artifacts | — |
| 2026-07-07 03:05 | detection | saas secret providers | Mapbox, Sentry, PostHog, Shopify secret patterns | — |

## Queued (not yet taken)

- **Reflected XSS canary probe** — inject unique canary into common query params, confirm unescaped reflection in HTML/JS response
- **Live Twilio key validation** — harmless Accounts API GET after paired credentials found (confirm token is live)
- **Resend / SendGrid live validation** — verify exposed email API keys without sending mail
- **CSRF on state-changing routes** — probe POST without Origin/Referer when session cookie present
- **Scheduled re-scan diffing** — feature: compare findings across monitor ticks

## Open PRs (do not duplicate)

See `gh pr list --state open` — PRs #1–#10 cover Mapbox/Sentry secrets, infra artifacts, open redirect, Auth0, Algolia, Convex probes, admin panel, JWT alg=none, Convex deploy key.
