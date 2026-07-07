# Automation Backlog

Hourly autonomous runs ship one focused detection PR each. **This file is the single source of truth** — do not duplicate entries across PR branches.

## Shipped this run

| Date (UTC) | Area | What shipped | Branch |
|------------|------|--------------|--------|
| 2026-07-07 19:00 | detection | Live Anthropic API key validation via Models API | `cursor/thugir-scanner-evolution-932b` (PR #26) |

**Follow-ups:** Stripe restricted-key (`rk_live_`) live validation; CSRF state-changing probe; MongoDB/Atlas connection string in client bundle.

## Open PRs (do not duplicate)

| PR | Area | Detection | Branch |
|----|------|-----------|--------|
| #1 | detection | Mapbox, Sentry, PostHog, Shopify secret patterns | `cursor/thugir-scanner-evolution-d94f` |
| #2 | detection | Exposed infra artifacts (Terraform, AWS, actuator) | `cursor/thugir-scanner-evolution-9233` |
| #3 | detection | Open redirect via query parameter probe | `cursor/thugir-scanner-evolution-d346` |
| #4 | detection | Auth0 OAuth client secret in client bundle | `cursor/thugir-scanner-evolution-9475` |
| #5 | detection | Algolia admin API key in client bundle | `cursor/thugir-scanner-evolution-afe6` |
| #6 | detection | Convex open-query probe for missing auth | `cursor/thugir-scanner-evolution-850a` |
| #7 | detection | Public S3/GCS/R2 bucket probe from client bundle URLs | `cursor/thugir-scanner-evolution-8f31` |
| #8 | detection | Exposed admin panel probe without authentication | `cursor/thugir-scanner-evolution-5f61` |
| #9 | detection | JWT alg=none acceptance probe | `cursor/thugir-scanner-evolution-69b6` |
| #10 | detection | Convex deploy key secret in client bundle | `cursor/thugir-scanner-evolution-68cd` |
| #12 | detection | Twilio auth token pairing (replaces loose SID regex) | `cursor/thugir-scanner-evolution-27fc` |
| #13 | detection | Reflected XSS canary probe via query parameters | `cursor/thugir-scanner-evolution-e4e1` |
| #15 | detection | SSTI canary probe via query parameters | `cursor/thugir-scanner-evolution-f0c2` |
| #17 | detection | Live Twilio credential validation via Accounts API | `cursor/thugir-scanner-evolution-925d` |
| #20 | detection | Live Stripe secret key validation via Balance API | `cursor/thugir-scanner-evolution-fdd0` |
| #22 | detection | Live OpenAI API key validation via Models API | `cursor/thugir-scanner-evolution-f74b` |
| #26 | detection | Live Anthropic API key validation via Models API | `cursor/thugir-scanner-evolution-932b` |

## Queued (not yet taken)

- **detection** — Stripe restricted key (`rk_live_*`) live validation.
- **detection** — CSRF probe on state-changing routes.
- **detection** — MongoDB / Atlas connection string in client bundle.
- **feature** — Wire admin `patterns` DB table into `runFreeScan` runtime merge.
- **feature** — Scheduled re-scans with finding diff.
- **frontend** — Evidence viewer polish + copy-fix-prompt buttons.

## Integrity rules

1. One detection per PR — never bundle backlog items into a detection PR.
2. Do not open a PR if an open PR or `main` already ships the same pattern slug (including modifications to an existing slug).
3. Use `auto/detection/*` or `cursor/thugir-scanner-evolution-*` branches for PRs.
4. Run `node web/scripts/pattern-catalog.mjs` after pattern changes.
5. Only flag secrets when live validation or positive proof succeeds — no regex-only findings for provider keys.
