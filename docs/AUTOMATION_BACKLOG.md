# Automation backlog

Hourly autonomous runs log shipped work and follow-ups here. Open PRs are checked before each run to avoid duplication.

## Open PRs (do not duplicate)

| PR | Area | Title | Branch |
|----|------|-------|--------|
| #1 | detection | Mapbox, Sentry, PostHog, Shopify secret patterns | `cursor/thugir-scanner-evolution-d94f` |
| #2 | detection | Probe exposed infra artifacts (Terraform, AWS, actuator) | `cursor/thugir-scanner-evolution-9233` |
| #3 | detection | Open redirect via query parameter probe | `cursor/thugir-scanner-evolution-d346` |

## Shipped

### 2026-07-07 — Auth0 OAuth client secret in client bundle

- **Area:** detection
- **Branch:** `auto/detection/auth0-oauth-client-secret`
- **What:** New `auth0SecretInClient` rule_ref + `vibe-auth0-secret-in-client` pattern. Flags `AUTH0_CLIENT_SECRET` / `AUTH0_M2M_*` env vars and `clientSecret` assignments near Auth0 config in shipped JS bundles.
- **Patterns:** 64 enabled (was 63)
- **Follow-ups:** Convex BaaS open-data probe; Upstash/Redis REST token regex; Algolia admin key; live Auth0 client-secret validation via token endpoint (careful rate limits); generic OAuth `client_secret` for non-Auth0 providers (GitHub, Google beyond GOCSPX prefix).

### 2026-07-07 — Open redirect (prior run, PR #3)

- **Area:** detection
- **What:** Query-parameter open redirect probe
- **Follow-ups:** Header-based redirect chains, post-login redirect params

### 2026-07-07 — Exposed infra artifacts (prior run, PR #2)

- **Area:** detection
- **What:** Terraform state, AWS creds, Spring actuator, kubeconfig http probes
- **Follow-ups:** CI token paths (.travis.yml secrets), PEM/id_rsa dotfiles

### 2026-07-07 — Mapbox/Sentry/PostHog/Shopify secrets (prior run, PR #1)

- **Area:** detection
- **What:** Additional secret_regex providers with format validation
- **Follow-ups:** Live key validation for each provider

## Backlog (not yet taken)

1. **Convex open data plane** — fingerprint + REST probe analogous to Supabase RLS
2. **Upstash Redis REST token** — `UPSTASH_*` in client bundles (common Lovable stack)
3. **Algolia / Meilisearch admin keys** — server-only search credentials in JS
4. **JWT signing secret in live bundle** — port codescan `jwt-alg-none` / hardcoded secret rules to URL scanner
5. **Scheduled re-scans + diffing** — feature: what changed since last scan
6. **Evidence viewer UX** — frontend: copy-fix-prompt, severity filters on scan results
7. **Regenerate pattern seed drift** — keep `supabase/seed/patterns.sql` in sync (ongoing)
