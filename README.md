# Thugir Scanner

**Security scanning for AI-built apps.** A commercial, multi-tenant, self-serve scanner that
finds the specific, repeatable misconfigurations that AI "vibe-coding" tools (Lovable, Bolt, v0,
Replit, Cursor, Base44, Windsurf, Copilot, …) ship by default — exposed secrets, open databases,
broken access control, downloadable `.env`/`.git`, and more. Every finding is backed by captured
evidence before it is flagged.

> This repository is the standalone product. The Deep Scan tier reuses the private `thugir-node`
> engine (see [Deep Scan engine](#deep-scan-engine)); the free tier is fully self-contained.

---

## Repository layout

```
thugir-scanner/
├── web/           Next.js 14 (App Router, TypeScript) → deploys to Vercel.
│                  Free-tier scan engine, Supabase auth, dashboard, admin panel,
│                  all API routes, and SEO/marketing pages.
├── worker/        Python (FastAPI) → deploys to Render/Fly.
│                  Deep Scan executor. Imports the thugir-node engine with hard caps.
├── supabase/      SQL migrations (0001–0006) + optional pattern seed.
├── docs/
│   ├── internal/  architecture, pattern-library spec, admin runbook, incident
│   │              response, dev setup, environment variables, decisions, moat/roadmap
│   └── external/  overview of the public SEO surfaces
└── WebDesignRules.md   Design system / brand guidelines for the marketing site.
```

## Product tiers

| Tier | What it does | Where it runs |
|---|---|---|
| **Free Starter Scan** | Single-request checks for the highest-impact AI-builder misconfigurations. Locked teaser cards prove there is more to find. | Entirely inside a Vercel function |
| **Deep Scan** (one-time, Razorpay) | Authenticated crawl + full pattern library + scoped `thugir-node` probes. Full evidence + paste-back fix prompts. Requires verified domain ownership. | Python worker |
| **Continuous Protection** (subscription) | Scheduled re-scans + monitoring on top of Deep Scan. | Worker + Supabase schedules |

## Core thesis

AI builders ship predictable, repeatable vulnerability patterns. The pattern library
(`web/lib/patterns` + the `patterns` table) is the product's IP and is designed so new patterns are
added **as data, not code**. Inventory the catalog with `node web/scripts/pattern-catalog.mjs`.

---

## Prerequisites

- **Node 20+**
- **Python 3.11+** (only for the Deep Scan worker)
- A **Supabase** project (auth + Postgres)
- An **Upstash** account (Redis rate-limiting + QStash job queue) — optional in dev
- **Razorpay** keys (test is fine) — optional in dev
- (Deep Scan only) access to the **`thugir-node`** engine

## Quick start (web, free tier)

```bash
cd web
cp .env.example .env.local     # fill in values, or set DEV_MODE=1 to bypass backends
npm install
npm run dev                    # http://localhost:3000
```

`DEV_MODE=1` bypasses Supabase/Upstash/Razorpay so you can exercise the scan engine and UI with no
backend. Set `DEV_TIER=free|deep|continuous` to preview tier-gated UI.

Useful commands (run from `web/`):

```bash
npm run build       # production build
npm run lint
npm run typecheck   # tsc --noEmit
node scripts/pattern-catalog.mjs   # list the pattern library
node scripts/smoke-scan.mjs        # smoke-test the scan engine
```

## Supabase setup

1. Create a Supabase project.
2. Apply the migrations in order (SQL editor, `supabase db push`, or the MCP):
   `supabase/migrations/0001_init.sql` … `0006_monitor_scan_link.sql`.
3. (Optional) Seed the DB-driven pattern table: `supabase/seed/patterns.sql`.
4. Under **Authentication**, enable **Email (magic link)** and **Google**.
5. Copy the project URL + anon key into `web/.env.local`
   (`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`). Grab the **service role** key
   from **Settings → API** and set `SUPABASE_SERVICE_ROLE_KEY` (server-only — never expose it).
6. Make yourself an admin:
   ```sql
   insert into admin_users (id, role) values ('<your auth.users.id>', 'owner');
   ```

Every table, RLS policy, and the `findings_visible` gating view is defined in
`supabase/migrations/0001_init.sql`. Full details: [docs/internal/architecture.md](docs/internal/architecture.md).

## Deep Scan engine

The Deep Scan `worker/` imports the private **`thugir-node`** framework. It resolves the engine in
this order (`worker/runner.py`):

1. `THUGIR_ENGINE_ROOT` env var (used in production/containers), then
2. a git submodule at `engine/` (the split-repo layout), then
3. a sibling `thugir-node/` checkout (monorepo layout).

To run Deep Scans from this standalone repo, either add `thugir-node` as a submodule at `engine/`:

```bash
git submodule add <thugir-node-repo-url> engine
```

or point `THUGIR_ENGINE_ROOT` at a local checkout. The **free tier does not need the engine.** See
[worker/README.md](worker/README.md).

## Deployment

- **Web** → Vercel. Import the repo, set the Root Directory to `web/`, and add the environment
  variables from [docs/internal/environment-variables.md](docs/internal/environment-variables.md).
- **Worker** → Render/Fly. Provide `THUGIR_ENGINE_ROOT` (or vendor the engine), Supabase service
  credentials, and the QStash signing keys. See [worker/README.md](worker/README.md).

## Key safety properties

- **Server-side blur** — gated finding fields are never sent to under-tier users
  (`web/lib/findings/gate.ts` + the `findings_visible` view).
- **SSRF/abuse guard** — refuses private/loopback/metadata targets.
- **Deep Scans require verified domain ownership** (file / meta tag / DNS TXT / well-known).
- **Admin panel** — layered auth (`admin_users` + roles), 2FA, append-only audit log, encrypted
  provider keys (only last-4 shown in the UI), `robots`-disallowed + `noindex`.
- **Razorpay webhooks** verify the signature against the raw body before granting entitlements.

## Documentation

| Doc | Purpose |
|---|---|
| [docs/internal/dev-setup.md](docs/internal/dev-setup.md) | Local development from scratch |
| [docs/internal/environment-variables.md](docs/internal/environment-variables.md) | Every environment variable |
| [docs/internal/architecture.md](docs/internal/architecture.md) | System architecture & data flow |
| [docs/internal/pattern-library-spec.md](docs/internal/pattern-library-spec.md) | How patterns are authored |
| [docs/internal/admin-runbook.md](docs/internal/admin-runbook.md) | Operating the admin panel |
| [docs/internal/incident-response.md](docs/internal/incident-response.md) | Incident response |
| [docs/internal/MOAT_AND_ROADMAP.md](docs/internal/MOAT_AND_ROADMAP.md) | Product moat & roadmap |
| [docs/internal/decisions.md](docs/internal/decisions.md) | Architecture decision log |

## License

Proprietary — © 2026 Thugir Labs. All rights reserved.
