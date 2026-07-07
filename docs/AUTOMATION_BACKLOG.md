# Automation backlog

Hourly autonomous runs ship one focused PR each. Items marked **done** are merged or open; do not duplicate.

## Shipped / open (2026-07-07)

| Date (UTC) | Area | Item | Branch / PR | Status |
|------------|------|------|-------------|--------|
| 2026-07-07 03:05 | detection | Mapbox, Sentry, PostHog, Shopify secret patterns | `cursor/thugir-scanner-evolution-d94f` | open PR #1 |
| 2026-07-07 04:05 | detection | Exposed infra artifacts (Terraform, AWS, actuator) | `cursor/thugir-scanner-evolution-9233` | open PR #2 |
| 2026-07-07 05:06 | detection | Open redirect via query parameter probe | `cursor/thugir-scanner-evolution-d346` | open PR #3 |
| 2026-07-07 06:07 | detection | Auth0 OAuth client secret in client bundle | `cursor/thugir-scanner-evolution-9475` | open PR #4 |
| 2026-07-07 07:05 | detection | Algolia admin API key in client bundle | `cursor/thugir-scanner-evolution-afe6` | open PR #5 |
| 2026-07-07 08:06 | detection | Convex open-query probe for missing auth | `cursor/thugir-scanner-evolution-850a` | open PR #6 |
| 2026-07-07 09:06 | detection | Public S3/GCS/R2 bucket probe from client bundle URLs | `cursor/thugir-scanner-evolution-8f31` | open PR #7 |
| 2026-07-07 10:07 | detection | Exposed admin panel probe without authentication | `cursor/thugir-scanner-evolution-5f61` | open PR #8 |
| 2026-07-07 11:09 | detection | JWT alg=none acceptance probe | `cursor/thugir-scanner-evolution-69b6` | open PR #9 |
| 2026-07-07 12:01 | detection | Convex deploy key secret in client bundle | `auto/detection/convex-deploy-key-secret` | this run |

## Follow-ups (prioritized)

1. **Twilio auth token pairing** — require auth token hex near Account SID; avoid standalone 32-char hex FPs.
2. **Reflected XSS marker probe** — safe canary param reflection check on common query names.
3. **Dependency CVE scan** — parse package.json/lockfiles → OSV lookup (feature slice: read-only manifest fetch).
4. **CSRF on state-changing routes** — probe POST without Origin/Referer (deep tier).
5. **Merge/deconflict open PRs #1–#9** — human review queue is backing up.

## Notes

- Pattern count after 12:01 run: 65 enabled patterns (was 64).
- `npm run lint` may prompt interactively without `.eslintrc`; rely on `npm run build` lint step for CI parity.
