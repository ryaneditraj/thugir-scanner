# Automation Backlog

Hourly autonomous runs ship one focused detection PR each. **This file is the single source of truth** — do not duplicate entries across PR branches. The `manage-pr-integrity` script audits open PRs before each run.

## Shipped to main (2026-07-09)

| Slugs | Source | Notes |
|-------|--------|-------|
| `secret-mapbox-sk`, `secret-sentry-auth`, `secret-posthog-personal`, `secret-shopify-admin` | PR #1 | Merged manually — close PR #1 on GitHub |

## Open PRs (do not duplicate)

| PR | Area | Detection | Branch | Status |
|----|------|-----------|--------|--------|
| #1 | detection | Mapbox, Sentry, PostHog, Shopify secret patterns | `cursor/thugir-scanner-evolution-d94f` | **Shipped** — close shell |
| #2 | detection | Exposed infra artifacts (Terraform, AWS, actuator) | `cursor/thugir-scanner-evolution-9233` | DEAD BRANCH — close |
| #3 | detection | Open redirect via query parameter probe | `cursor/thugir-scanner-evolution-d346` | DEAD BRANCH — close |
| #4 | detection | Auth0 OAuth client secret in client bundle | `cursor/thugir-scanner-evolution-9475` | DEAD BRANCH — close |
| #5 | detection | Algolia admin API key in client bundle | `cursor/thugir-scanner-evolution-afe6` | DEAD BRANCH — close |
| #6 | detection | Convex open-query probe for missing auth | `cursor/thugir-scanner-evolution-850a` | DEAD BRANCH — close |
| #7 | detection | Public S3/GCS/R2 bucket probe from client bundle URLs | `cursor/thugir-scanner-evolution-8f31` | DEAD BRANCH — close |
| #8 | detection | Exposed admin panel probe without authentication | `cursor/thugir-scanner-evolution-5f61` | DEAD BRANCH — close |
| #9 | detection | JWT alg=none acceptance probe | `cursor/thugir-scanner-evolution-69b6` | DEAD BRANCH — close |
| #10 | detection | Convex deploy key secret in client bundle | `cursor/thugir-scanner-evolution-68cd` | DEAD BRANCH — close |
| #12 | detection | Twilio auth token pairing (replaces loose SID regex) | `cursor/thugir-scanner-evolution-27fc` | DEAD BRANCH — close |
| #13 | detection | Reflected XSS canary probe via query parameters | `cursor/thugir-scanner-evolution-e4e1` | DEAD BRANCH — close |
| #15 | detection | SSTI canary probe via query parameters | `cursor/thugir-scanner-evolution-f0c2` | DEAD BRANCH — close |
| #20 | detection | Live Stripe secret key validation via Balance API | `cursor/thugir-scanner-evolution-fdd0` | DEAD BRANCH — close |
| #22 | detection | Live OpenAI API key validation via Models API | `cursor/thugir-scanner-evolution-f74b` | DEAD BRANCH — close |
| #26 | detection | Live Anthropic API key validation via Models API | `cursor/thugir-scanner-evolution-932b` | DEAD BRANCH — close |
| #23 | dev | Development environment setup + AGENTS.md | `cursor/setup-dev-environment-0829` | DEAD BRANCH — close |

## Retired PR shells (close on GitHub UI)

Branch deleted — automations cannot `gh pr close` (token lacks permission). **Close all of these manually:**

- **#1** — patterns shipped to main
- **#2–#10, #12–#13, #15, #20, #22, #23, #26** — detection branches deleted by prior `--retire-superseded` run
- **#11, #14, #16, #17, #18, #19, #21, #25** — superseded integrity passes

After closing, run `cd web && node scripts/manage-pr-integrity.mjs --audit` — expect 0 open PRs.

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
5. Only one open integrity PR at a time — retire superseded integrity branches with `--retire-superseded` (safe default).
6. **Never** use `--retire-detection-duplicates` unless you intend to delete detection PR branches — it caused the #2–#26 branch loss.
