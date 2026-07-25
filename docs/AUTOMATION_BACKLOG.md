# Automation Backlog

Hourly autonomous runs ship one focused detection PR each. **This file is the single source of truth** — do not duplicate entries across PR branches.

## Shipped to main

| Batch | Slugs | Source |
|-------|-------|--------|
| 2026-07-09 | `secret-mapbox-sk`, `secret-sentry-auth`, `secret-posthog-personal`, `secret-shopify-admin` | PR #1 → PR #34 |
| 2026-07-09 | `secret-convex-deploy-key`, `vibe-auth0-secret-in-client`, `vibe-algolia-admin-in-client`, `jwt-alg-none-accepted`, `convex-open-query-no-auth`, `vibe-public-cloud-storage-bucket`, `exposed-infra-artifacts`, `vibe-exposed-admin-panel` | Dead PRs #2–#26 recovered |
| 2026-07-09 | Upgraded: `secret-twilio`, `secret-stripe-live`, `secret-openai`, `secret-anthropic` (live validation / pairing) | Dead PRs #12, #20, #22, #26 |

## Close these PR shells (one-time)

Cloud agent token cannot close PRs. Run locally:

```bash
cd web && node scripts/close-orphan-prs.mjs --close
```

Or close manually on GitHub: **#1–#26** (all shipped or dead-branch), plus integrity shells **#11, #14, #16–#21, #25**.

After closing: `cd web && node scripts/manage-pr-integrity.mjs --audit` — expect 0 open PRs.

## Open PRs

_None — all prior detection work shipped or retired. Do not reopen #1–#26._

## Queued (not yet taken)

- **detection** — MongoDB / Atlas connection string in client bundle.
- **detection** — Open redirect active probe (slug `open-redirect-query-param` has client evidence; add server probe if missing).
- **feature** — Wire admin `patterns` DB table into `runFreeScan` runtime merge.
- **feature** — Scheduled re-scans with finding diff.
- **frontend** — Evidence viewer polish + copy-fix-prompt buttons.

## Integrity rules

1. One detection per PR — never bundle backlog items into a detection PR.
2. Do not open a PR if an open PR or `main` already ships the same pattern slug.
3. Use `cursor/thugir-scanner-evolution-*` branches for PRs.
4. Run `node web/scripts/manage-pr-integrity.mjs --audit` before opening a new detection PR.
5. `--retire-superseded` is safe default (integrity only). Never use `--retire-detection-duplicates` without human approval.
