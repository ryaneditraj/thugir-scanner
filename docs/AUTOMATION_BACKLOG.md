# Automation backlog

Hourly autonomous runs log shipped work here. Open PRs are checked to avoid duplicates.

## Shipped

| Date | Area | PR / branch | What shipped | Follow-ups |
|------|------|-------------|--------------|------------|
| 2026-07-07 | detection | `auto/detection/open-redirect-probe` | Open redirect detection: probes common `?next=` / `?redirect=` params on `/` and auth paths; flags only when server issues HTTP redirect or meta-refresh to injected probe host | Discover redirect param names from homepage links; probe `/api/auth/callback`; MongoDB connection string in client bundle |

## Open / in-flight (do not duplicate)

| PR | Area | Topic |
|----|------|-------|
| #1 (draft) | detection | Mapbox, Sentry, PostHog, Shopify secret patterns |
| #2 (draft) | detection | Exposed infra artifacts (Terraform, AWS, actuator) |

## Backlog (not yet taken)

- MongoDB / Atlas connection string in client bundle (`secret_regex` + inline state parity)
- Algolia API key pattern in JS bundles
- Convex backend exposure checks (fingerprint exists, no patterns yet)
- JWT alg=none runtime probe (codescan rule exists; not in free HTTP scan)
- Scheduled re-scans + diffing
- SARIF export for CI
