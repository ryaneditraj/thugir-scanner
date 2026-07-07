# Automation Backlog

Hourly autonomous runs ship one focused detection PR each. **This file is the single source of truth** — do not duplicate entries across PR branches. The `manage-pr-integrity` script audits open PRs before each run.

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
| #19 | infra | PR integrity audit, backlog sync, duplicate detection | `cursor/pull-request-integrity-a924` |

> **Must close manually (automation token lacks `closePullRequest`):**
> - **#17** — duplicate `secret-twilio` modification; superseded by PR #12.
> - **#18** (`cursor/pull-request-integrity-8f98`) — superseded by PR #19.
> - **#16** (`cursor/pull-request-integrity-1ac1`) — superseded.
> - **#14** — dead branch `cursor/pull-request-integrity-e6ce`; superseded.
> - **#11** (`cursor/pull-request-integrity-447d`) — superseded.

## Queued (not yet taken)

- **detection** — MongoDB / Atlas connection string in client bundle.
- **feature** — Wire admin `patterns` DB table into `runFreeScan` runtime merge.
- **feature** — Scheduled re-scans with finding diff.
- **frontend** — Evidence viewer polish + copy-fix-prompt buttons.

## Integrity rules

1. One detection per PR — never bundle backlog items into a detection PR.
2. Do not open a PR if an open PR or `main` already ships the same pattern slug (including modifications to an existing slug).
3. Use `cursor/thugir-scanner-evolution-*` branches for PRs; do not create parallel `auto/detection/*` branches.
4. Run `node web/scripts/manage-pr-integrity.mjs --audit` before opening a new detection PR.
5. Only one open integrity PR at a time — close superseded duplicates before opening a new one.
