# Pattern library format spec

A **pattern** is one known, recurring vulnerability an AI builder tends to ship. Patterns are
the product's defensible IP. They are designed as **data** so new ones can be added as rows in
the `patterns` table with no redeploy.

Two sources, merged at runtime:
- **Code-defined** (canonical seed): [web/lib/patterns/](../../web/lib/patterns) - `STATIC_PATTERNS`.
- **DB-defined** (runtime, admin-managed): the `patterns` table, edited via the admin panel.

## Fields

- `slug` (unique), `platform`, `category`, `severity_default` (critical|high|medium|low|info)
- `title`, `description`, `impact_oneline` (founder-readable; ALWAYS shown, even when locked)
- `tier_required` (free|deep|continuous) - free patterns run on the free scan; higher tiers
  appear as locked teasers on a free scan and unlock with the matching paid scan.
- `detector_kind` + `detector_config` - how to evaluate it (below)
- `remediation` (`{summary, steps[]}`), `fix_prompt` (paste-back text), `version`, `enabled`

## Detector kinds

### `secret_regex`
Scan fetched JS/HTML for a high-precision credential pattern.
```jsonc
{ "regex": "sk_live_[A-Za-z0-9]{20,}", "secretName": "Stripe live secret key",
  "serverOnly": true, "validate": "optional substring/decoded-claim the match must contain" }
```
Keep regexes distinctive (unique prefixes/shapes). False positives kill trust on a free tool.
For JWTs, `validate` is matched against the decoded payload (e.g. `service_role`).

### `http_probe`
Fetch fixed paths and assert on the response. Single-request, cheap.
```jsonc
{ "paths": ["/.env", "/.env.local"],
  "expect": { "kind": "body_regex", "regex": "[A-Z0-9_]+=" },
  "maxBytes": 4096 }
```
`expect.kind`: `status_2xx` | `status_2xx_non_html` | `body_contains` | `body_regex` |
`header_absent` | `header_present`.

### `rule_ref`
Defer to a named TS rule in [web/lib/checks/registry.ts](../../web/lib/checks/registry.ts) for
multi-signal logic.
```jsonc
{ "rule": "supabaseRls", "options": { "harmlessProbe": true } }
```
Free-tier rules are registered in `FREE_RULES`. Deep-tier rule keys exist but are no-ops on the
free path (executed by the worker instead).

### Vibe-coded research pack (`lib/patterns/vibecode.ts`)

Patterns grounded in 2025 audits of Lovable/Bolt/v0/Replit deploys (vibe-eval, securityscanner.dev):

| Rule | What it catches |
|------|-----------------|
| `openApiDocs` | `/openapi.json`, `/swagger.json`, etc. reachable without auth |
| `demoModeFlags` | `SKIP_AUTH`, `DEMO_MODE`, `BYPASS_AUTH` left `true` in client bundle |
| `supabaseStoragePublic` | Supabase bucket with `public: true` listable via anon key |
| `supabaseServiceRoleClient` | `service_role` JWT passed to `createClient()` in browser JS |
| `supabaseRls` | Unauthenticated rows returned from PostgREST (existing) |
| `sitemapSensitivePaths` | `/admin`, `/staging`, etc. listed in sitemap.xml |
| `weakCsp` | CSP present but includes `unsafe-inline` / `unsafe-eval` |
| `hardcodedCredentials` | Literal admin/password or demo emails in client JS |
| `clerkSecretInClient` | Clerk `sk_live_` / `sk_test_` assigned in browser code |
| `firebaseFirestoreOpen` | Firestore REST returns documents without auth token |
| `exposedAdminPanel` | `/admin`, `/dashboard` return admin UI without login redirect |
| http_probe | `/.streamlit/secrets.toml` on Streamlit vibe deploys |

Builder-specific aliases (Lovable storage, Bolt demo mode, v0 OpenAPI) share the same rules so
platform detection prioritises the right fix prompts.

## Adding a new pattern (no redeploy)

1. In the admin panel: **Patterns -> New pattern**. Fill the fields; put detector JSON in
   `detector_config`.
2. For `secret_regex` / `http_probe`, that is all - the free engine reads them from the DB merge.
3. For `rule_ref` with a brand-new rule, you must also add the rule function to
   `registry.ts` and ship it (this is the only case that needs a deploy).
4. Every create/edit snapshots a row into `pattern_versions` and writes to `admin_audit_log`.

## Tiering rule (which tier a pattern belongs to)

A pattern is `free` iff it is (a) cheap - single request, no crawl/auth/multi-step; (b) very
common in AI-built apps specifically; (c) clear money/data/account business impact. Otherwise it
is `deep`.
