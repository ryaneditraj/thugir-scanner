# Automation backlog

Hourly agent run log. Open PRs are deconflicted before each run — do not duplicate items listed as **open** or **shipped**.

## Shipped

| Date (UTC) | Area | Branch / PR | What shipped | Follow-ups |
|------------|------|-------------|--------------|------------|
| 2026-07-07 | detection | `auto/detection/reflected-xss-probe` | Reflected XSS canary probe — injects `"><thugir-xss-canary>` into common query params; flags unescaped HTML echo | SSTI canary probe; DOM-based XSS via bundle param wiring |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-27fc` (open) | Twilio auth token pairing | Live Twilio key validation |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-68cd` (open) | Convex deploy key secret | Convex admin URL probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-69b6` (open) | JWT alg=none acceptance probe | JWT weak-secret probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-5f61` (open) | Exposed admin panel probe | Discover admin paths from bundle |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-8f31` (open) | Public S3/GCS/R2 bucket probe | Azure blob public probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-850a` (open) | Convex open-query probe | Convex mutation auth probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-afe6` (open) | Algolia admin API key in client | Algolia index ACL probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-9475` (open) | Auth0 OAuth client secret in client | Auth0 M2M key probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-d346` (open) | Open redirect via query param | Post-login redirect chain probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-9233` (open) | Exposed infra artifacts (Terraform, actuator) | Kubernetes dashboard probe |
| 2026-07-07 | detection | `cursor/thugir-scanner-evolution-d94f` (open) | Mapbox, Sentry, PostHog, Shopify secret patterns | Live key validation for each provider |

## Queued (not yet taken)

- SSTI canary probe (`{{7*7}}` / `${7*7}` reflection in template engines)
- Live Twilio key validation (pair SID + token against API)
- CSRF token missing on state-changing routes (deep tier)
- Subdomain takeover fingerprints (dangling CNAME)
- SPF/DMARC/DKIM posture grading
- Scheduled re-scan diffing (feature)
- SARIF export for CI (feature)
- Evidence viewer UX polish (frontend)
