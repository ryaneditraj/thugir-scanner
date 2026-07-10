# Thugir Scanner — Everything (A to Z)

Complete reference for everything implemented in this project.

**Product:** Thugir Scanner by Thugir Labs  
**Version:** 0.1.0  
**License:** Proprietary © 2026 Thugir Labs

---

## Table of contents

1. [What is Thugir](#1-what-is-thugir)
2. [Core thesis](#2-core-thesis)
3. [Architecture](#3-architecture)
4. [Repository layout](#4-repository-layout)
5. [Product tiers](#5-product-tiers)
6. [Scan engine](#6-scan-engine)
7. [Pattern library](#7-pattern-library)
8. [AI layers](#8-ai-layers)
9. [Thugir Agent Engine](#9-thugir-agent-engine)
10. [Methodology framework](#10-methodology-framework)
11. [Web application](#11-web-application)
12. [API reference](#12-api-reference)
13. [Authentication and authorization](#13-authentication-and-authorization)
14. [Billing and entitlements](#14-billing-and-entitlements)
15. [Admin panel](#15-admin-panel)
16. [Database schema](#16-database-schema)
17. [Deep Scan worker](#17-deep-scan-worker)
18. [Continuous protection](#18-continuous-protection)
19. [Safety and security](#19-safety-and-security)
20. [Environment variables](#20-environment-variables)
21. [Development setup](#21-development-setup)
22. [Deployment](#22-deployment)
23. [Testing](#23-testing)
24. [Scripts and tooling](#24-scripts-and-tooling)
25. [Documentation index](#25-documentation-index)
26. [Roadmap](#26-roadmap)

---

## 1. What is Thugir

Thugir Scanner is a **commercial, multi-tenant, self-serve security scanner** built specifically
for web applications created with AI coding tools. It finds the predictable, repeatable
misconfigurations that AI builders ship by default:

- Exposed API keys and secrets in client bundles
- Open Supabase/Firebase databases without row-level security
- Downloadable `.env`, `.git`, and backup files
- Broken access control and IDOR
- Missing security headers and weak CSP
- Demo-mode auth bypass flags left in production
- Injection flaws (XSS, SQLi, SSTI) with evidence-based proof

Every finding is backed by **captured evidence** before it is reported. Thugir does not guess.

---

## 2. Core thesis

AI builders (Lovable, Bolt, v0, Replit, Cursor, Windsurf, Copilot, Base44, etc.) ship
predictable vulnerability patterns. The **pattern library** is Thugir's core IP — new detections
are added as **data, not code**. The scanner inventory currently holds **133 patterns** across
**9 platforms**.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Vercel (Next.js 14)                                        │
│  ├── Marketing + SEO pages                                  │
│  ├── Auth (Supabase)                                          │
│  ├── Dashboard + scan reports                                 │
│  ├── Admin panel                                              │
│  ├── Free-tier scan engine (TypeScript)                       │
│  └── Deep scan orchestration (inline or QStash → worker)     │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   ┌──────────┐      ┌──────────────┐     ┌──────────────┐
   │ Supabase │      │ Upstash      │     │ Razorpay     │
   │ Postgres │      │ Redis+QStash │     │ Payments     │
   │ + Auth   │      │ Rate limits  │     │ Webhooks     │
   └──────────┘      └──────────────┘     └──────────────┘
                            │
                            ▼
              ┌──────────────────────────┐
              │ Python Worker (Render) │
              │ Deep Scan executor     │
              │ + thugir-node engine   │
              └──────────────────────────┘
                            │
                            ▼ (optional)
              ┌──────────────────────────┐
              │ Thugir Agent Engine      │
              │ Python AI pentester      │
              │ (local/worker only)      │
              └──────────────────────────┘
```

**Two deployables, never sharing a process:**
- **web/** — Next.js on Vercel (free tier + orchestration)
- **worker/** — Python FastAPI on Render/Fly (deep tier execution)

They communicate via Supabase (data) and QStash (job queue).

---

## 4. Repository layout

```
thugir-scanner/
├── web/                        Next.js 14 app (TypeScript)
│   ├── app/                    Pages + API routes
│   │   ├── (marketing)/        Landing, demo, SEO, legal
│   │   ├── (app)/              Dashboard, scan reports
│   │   ├── (admin)/            Admin panel
│   │   └── api/                REST API endpoints
│   ├── components/             Shared UI (11 components)
│   ├── lib/                    Core business logic
│   │   ├── checks/             Scan engine + 133 rule implementations
│   │   ├── patterns/           Pattern library definitions
│   │   ├── agent/              Thugir Agent Engine bridge
│   │   ├── ai/                 AI analyst + deep probe
│   │   ├── methodology/        Reflexion, blackboard, evidence gate, skills
│   │   ├── findings/           Tier gating, max-damage, blur
│   │   ├── auth/               Admin auth + roles
│   │   ├── razorpay/           Billing (sacred zone — do not auto-edit)
│   │   ├── supabase/           DB clients
│   │   ├── settings/           Platform settings store
│   │   └── scans/              Scan enrichment pipeline
│   ├── scripts/                Dev/CI tooling
│   └── middleware.ts           Auth gate
├── worker/                     Python Deep Scan worker (FastAPI)
├── services/thugir-agent/      Thugir Agent Engine (Python AI pentester)
├── supabase/
│   ├── migrations/             0001–0006 SQL migrations
│   └── seed/patterns.sql       133 pattern seed data
├── docs/
│   ├── HACKATHON_GUIDE.md      Quick demo guide
│   ├── internal/               Architecture, runbooks, skills library
│   └── external/               Public SEO surface spec
├── everything.md               This file
├── README.md                   Project overview
└── WebDesignRules.md           Design system guidelines
```

---

## 5. Product tiers

| Tier | Price | What it does | Where it runs |
|------|-------|--------------|---------------|
| **Free Starter Scan** | Free | Single-request checks for highest-impact misconfigs. Locked teaser cards for deep findings. | Vercel function |
| **Deep Scan** | ₹499 one-time | Full crawl + 133 patterns + AI analysis + fix prompts. Domain ownership verification. | Worker + Vercel |
| **Continuous Protection** | Subscription | Scheduled re-scans + monitoring on verified domains. | Worker + cron |

### Tier gating mechanics

- Gated finding fields (`evidence`, `remediation`, `fixPrompt`) are **never sent** to under-tier users
- Implemented in `web/lib/findings/gate.ts` + SQL view `findings_visible`
- Not hidden via CSS — data is absent from API responses and DOM

---

## 6. Scan engine

### Free scan (`POST /api/scan/free`)

Runs entirely in a Vercel serverless function:

1. Normalize + SSRF-guard the target (refuse private/loopback/metadata hosts)
2. Fetch homepage + up to 12 same-origin scripts (byte-capped)
3. Apply `tier_required='free'` patterns (77 patterns)
4. Detect the AI builder platform (`web/lib/detect`)
5. Return free findings + deep-tier locked teasers
6. Optional AI analyst enrichment

**Entry point:** `web/lib/checks/runner.ts` → `runFreeScan()`

### Deep scan (`POST /api/scan/deep` or `/api/scan/deep-run`)

1. Crawl up to 6 pages + scripts (byte-capped)
2. Run all 133 patterns including deep-tier rules (56 deep patterns)
3. AI deep probe on combined HTML/JS
4. Optional Thugir Agent Engine enrichment
5. AI analyst for tailored fixes and max-damage overlay

**Entry point:** `web/lib/checks/runner.ts` → `runDeepScan()`

### Code scan (`POST /api/scan/code`)

Scans a GitHub repository for secrets and misconfigs in source files.

### Agent scan (`POST /api/scan/agent`)

Runs the Thugir Agent Engine (Python) for autonomous AI penetration testing.
Requires Python 3.10+ and LLM API key on the host.

### Detection kinds

| Kind | Description | Example |
|------|-------------|---------|
| `rule_ref` | TypeScript rule function | `supabaseRls`, `thugirJwtClaims` |
| `secret_regex` | Regex match in bundle | Stripe live keys, AWS AKIDs |
| `http_probe` | Fixed path HTTP check | `/.env`, `/.git/HEAD` |
| `platform_specific` | Builder-specific checks | Lovable Supabase patterns |

### Power rules (native TypeScript)

| Rule | Tier | Detection |
|------|------|-----------|
| `thugirJwtClaims` | Free | Weak JWT alg/missing claims in client bundle |
| `thugirJsEndpoints` | Free | Admin/debug/graphql paths in shipped JS |
| `thugirDirEnum` | Deep | Directory probing (actuator, swagger, .git) |
| `reflexionEscalatedXss` | Deep | WAF-bypass XSS with L0–L3 encoding |
| `reflexionEscalatedSqli` | Deep | Escalated SQLi error-based probes |
| `reflexionEscalatedSsti` | Deep | Multi-template SSTI (7×7 → 49) |

### Platform detection

Detects which AI builder created the target app:
Lovable, Bolt, v0, Replit, Cursor, Windsurf, Firebase, Supabase, generic.

---

## 7. Pattern library

**133 patterns** across 9 platforms:

| Platform | Count | Examples |
|----------|-------|---------|
| generic | 115 | Security headers, XSS, SQLi, CORS, secrets |
| supabase | 4 | RLS missing, service role in client, storage public |
| firebase | 3 | Open rules, Firestore open |
| lovable | 2 | Supabase storage, client-only auth |
| bolt | 2 | Platform-specific misconfigs |
| v0 | 3 | Server action authz, patterns |
| replit | 2 | Platform-specific |
| cursor | 1 | Platform-specific |
| windsurf | 1 | Platform-specific |

**Tier breakdown:** 77 free, 56 deep, 0 continuous

### Pattern structure

Each pattern in `web/lib/patterns/generic.ts` contains:

```typescript
{
  slug: string;              // unique identifier
  platform: string;          // target platform
  category: string;          // OWASP category
  severityDefault: Severity;  // critical|high|medium|low
  title: string;
  description: string;
  impactOneline: string;
  detectorKind: string;     // rule_ref|secret_regex|http_probe
  detectorConfig: object;    // rule name or regex or paths
  tierRequired: TierName;   // free|deep|continuous
  remediation: { summary, steps };
  fixPrompt: string;         // paste-back fix for AI tools
  version: number;
  enabled: boolean;
}
```

### Managing patterns

```bash
cd web && npm run patterns    # regenerate catalog + SQL seed
node scripts/pattern-catalog.mjs  # list all patterns as JSON
```

Admin CRUD at `/admin/patterns` with API at `/api/admin/patterns`.

---

## 8. AI layers

### AI Deep Probe (`web/lib/ai/deep-probe.ts`)

- Reads crawled HTML/JS excerpts
- LLM proposes vulnerabilities with **verbatim evidence quotes**
- Unverified proposals (quote not in source) are discarded
- Uses WSTG oracle skills + agent oracle skills + reflexion guidance
- Max 8 findings per scan

### AI Analyst (`web/lib/ai/analyze.ts`)

- Runs after scan completes
- Generates risk summary, attack chain, max company damage
- Tailored fix prompts per finding slug
- Configurable per tier (model, temperature, tokens)

### Configuration

- Provider: OpenRouter (default model: `anthropic/claude-3.5-haiku`)
- Env: `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`
- Admin settings at `/admin/settings` for per-tier AI config
- Scans work without AI — it enhances results when available

---

## 9. Thugir Agent Engine

Optional Python AI penetration testing layer at `services/thugir-agent/`.

### Components

| Component | Purpose |
|-----------|---------|
| `thugir_runner.py` | JSON stdin/stdout bridge for headless scans |
| Agent solver | OODA-loop goal-driven penetration testing |
| MCP tools | HTTP, browser, traffic capture, replay |
| Skills library | 21+ pentest skills (recon, exploitation, WAF bypass) |
| Traffic store | Request/response evidence capture |
| Report generator | Structured findings with verification status |

### TypeScript bridge (`web/lib/agent/`)

| File | Purpose |
|------|---------|
| `bridge.ts` | Spawn Python runner, check availability |
| `types.ts` | Request/result type definitions |
| `findings-mapper.ts` | Map agent findings → PatternFinding |
| `index.ts` | Public exports |

### When it runs

- `POST /api/scan/agent` — explicit agent scan API
- Deep scan enrichment — auto-chains when `THUGIR_AGENT_SCAN_ENABLED=1`
- Power scan CLI — `--agent` flag

### Setup

```bash
pip install -r services/thugir-agent/requirements.txt
export THUGIR_AGENT_LLM_API_KEY=sk-...
cd web && npm run agent-check
```

---

## 10. Methodology framework

Located in `web/lib/methodology/`:

| Module | File | Purpose |
|--------|------|---------|
| Three-gate | `three-gate.ts` | Recon → Test → Verify discipline |
| Evidence gate | `evidence-gate.ts` | Claims must have verbatim proof |
| Severity triage | `severity-triage.ts` | Downgrade hardening-only to low |
| Reflexion | `reflexion.ts` | L0–L4 payload encoding escalation |
| Blackboard | `blackboard.ts` | Fact/intent tracking for probe memory |
| Coverage | `coverage.ts` | Track tested vulnerability classes |
| Skills | `skills.ts` | Load 141 WSTG/attack playbooks |
| Prompts | `prompts.ts` | System prompt fragments for AI layers |

### Security skills library

`docs/internal/security-skills/` — 141 skills:

- ~120 OWASP WSTG 4.2 test procedures
- ~20 attack playbooks (SSRF, JWT, IDOR, SSTI, etc.)
- Indexed in `index.json` with id, category, owasp_id

---

## 11. Web application

### Marketing pages

| Route | Purpose |
|-------|---------|
| `/` | Landing page + free scan form |
| `/how-scans-work` | Scan methodology explainer |
| `/demo` | Static sample report |
| `/report/sample` | Redacted Deep Scan sample |
| `/platforms/[platform]` | Per-builder SEO (8 platforms) |
| `/vulnerabilities/[slug]` | Per-pattern SEO (133 pages) |
| `/terms` | Terms of Service |
| `/privacy` | Privacy Policy |
| `/verify/[badgeId]` | Public scan verification badge |

### App pages (auth required)

| Route | Purpose |
|-------|---------|
| `/login` | Magic link + Google OAuth |
| `/dashboard` | Account portal, plan badge, scan history |
| `/scans/[id]` | Full scan report with tier-gated findings |

### Dashboard features

- **App URL scan** — scan any URL from dashboard
- **GitHub code scan** — scan a repo for secrets
- **Upgrade panel** — Razorpay checkout for Deep/Continuous
- **Deep scan panel** — domain verification + deep scan queue
- **Monitors panel** — continuous protection (continuous tier)
- **Scan history** — last 25 scans with status and platform

### Components

| Component | Purpose |
|-----------|---------|
| `ScanForm.tsx` | Landing page scan input |
| `DashboardPortal.tsx` | Dashboard scan tabs |
| `UpgradePanel.tsx` | Razorpay payment flow |
| `DeepScanPanel.tsx` | Domain verification UI |
| `MonitorsPanel.tsx` | Monitor management |
| `SignOutButton.tsx` | Auth sign-out |
| `NavBar.tsx` | Site navigation |
| `Footer.tsx` | Site footer |

---

## 12. API reference

### Scan APIs

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| POST | `/api/scan/free` | Optional | Free-tier scan |
| POST | `/api/scan/deep` | Required | Queue deep scan via QStash |
| POST | `/api/scan/deep-run` | Dev/power | Inline deep scan |
| POST | `/api/scan/code` | Required | GitHub repo scan |
| POST | `/api/scan/agent` | Dev/worker | Agent engine scan |
| GET | `/api/scan/agent` | Public | Agent availability check |

### Billing APIs

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/billing/create-order` | Create Razorpay order |
| POST | `/api/billing/verify` | Verify payment signature |
| POST | `/api/webhooks/razorpay` | Webhook for entitlements |

### Admin APIs

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET/POST | `/api/admin/patterns` | Pattern CRUD |
| GET/PATCH/DELETE | `/api/admin/patterns/[id]` | Single pattern |
| POST | `/api/admin/scans/[id]/kill` | Kill running scan |
| GET/POST | `/api/admin/settings` | Platform settings |
| GET/POST | `/api/admin/api-keys` | Encrypted provider keys |
| POST | `/api/admin/ai-test` | Test AI provider |
| POST | `/api/admin/preview-tier` | Preview tier gating |

### Other APIs

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/ownership/verify` | Domain ownership attestation |
| POST | `/api/worker/complete` | Worker scan completion callback |
| GET/POST | `/api/monitors` | Continuous monitor CRUD |
| GET | `/api/cron/monitors` | Cron-triggered monitor scans |
| GET | `/api/health` | Health check |

---

## 13. Authentication and authorization

### User auth (Supabase)

- Magic link email
- Google OAuth
- Session managed via `@supabase/ssr` cookies
- Middleware protects `/dashboard`, `/scans/*`, `/admin/*`

### Admin auth

- `admin_users` table with roles: `owner`, `analyst`, `support`
- Checked in `web/lib/auth/admin.ts`
- Admin routes return 403 for non-admins
- `robots.txt` disallows `/admin`, pages have `noindex`

### Dev mode bypass

```env
DEV_MODE=1          # Skip auth, no DB persistence
DEV_TIER=deep       # Preview tier-gated UI
```

---

## 14. Billing and entitlements

### Razorpay integration

- **Deep Scan:** one-time payment (default ₹499 / 49900 paise)
- **Continuous Protection:** recurring subscription
- Checkout in `UpgradePanel.tsx` (sacred zone)
- Webhook at `/api/webhooks/razorpay` verifies signature against raw body
- Entitlements stored in `profiles` table (`tier`, `deep_credits`, `subscription_status`)

### Entitlement resolution

`web/lib/entitlements.ts` → `resolveUserTier(userId)`:
1. Check admin tier override
2. Check active subscription
3. Check deep credits
4. Default to `free`

---

## 15. Admin panel

| Route | Purpose |
|-------|---------|
| `/admin` | Health overview (Supabase, Razorpay, Worker, AI, Agent) |
| `/admin/settings` | Platform settings (AI config, maintenance mode) |
| `/admin/patterns` | Pattern library CRUD |
| `/admin/scans` | Scan management + kill |
| `/admin/users` | User management |
| `/admin/keys` | Encrypted provider API keys (last-4 shown) |
| `/admin/audit` | Append-only audit log |

### Health dashboard metrics

- Total scans, active patterns, open critical findings, user profiles
- Integration status: Supabase, Razorpay, Worker, AI analyst, Agent engine

---

## 16. Database schema

### Migrations (`supabase/migrations/`)

| Migration | Purpose |
|-----------|---------|
| `0001_init.sql` | Core tables, RLS, findings_visible view |
| `0002_platform_settings.sql` | Settings store |
| `0003_admin_tier_overrides.sql` | Admin tier overrides |
| `0004_razorpay_idempotency.sql` | Payment idempotency |
| `0005_continuous_monitors.sql` | Monitor schedules |
| `0006_monitor_scan_link.sql` | Monitor-to-scan linking |

### Core tables

| Table | Purpose |
|-------|---------|
| `profiles` | User tier, credits, subscription |
| `scans` | Scan jobs (target, tier, status, platform) |
| `findings` | Individual findings per scan |
| `patterns` | DB-driven pattern library (optional, static fallback) |
| `admin_users` | Admin roles |
| `audit_log` | Append-only admin actions |
| `platform_settings` | JSON settings store |
| `monitors` | Continuous protection schedules |
| `api_keys` | Encrypted provider keys |

### RLS policies

- Users see only their own scans and findings
- `findings_visible` view enforces tier gating at SQL level
- Admin service role bypasses RLS for operator actions

---

## 17. Deep Scan worker

Python FastAPI service at `worker/`:

```
POST /run → runner.run_deep_scan() → thugir-node engine → Supabase
```

### Engine resolution (`worker/runner.py`)

1. `THUGIR_ENGINE_ROOT` env var
2. Git submodule at `engine/`
3. Sibling `thugir-node/` checkout

### Capabilities

- Multi-page crawl with byte caps
- External tool integration (nmap, nikto, nuclei) when available
- Finding normalization via `finalize_findings`
- Cooperative cancel via `scans.status='killed'`
- QStash signature verification

### Worker callback

Worker POSTs results to `/api/worker/complete` with `WORKER_CALLBACK_SECRET`.

---

## 18. Continuous protection

- Users on Continuous tier create monitors for verified domains
- Cron at `/api/cron/monitors` triggers scheduled re-scans
- Delta detection: new findings since last scan
- Optional email alerts via Resend
- Monitor CRUD at `/api/monitors` and dashboard `MonitorsPanel`

---

## 19. Safety and security

| Property | Implementation |
|----------|----------------|
| SSRF guard | Refuses private/loopback/metadata IPs |
| Server-side blur | Gated fields never in API response |
| Domain ownership | File/meta/DNS/well-known verification |
| Rate limiting | Upstash Redis per-IP and per-user |
| Webhook verification | Razorpay signature on raw body |
| Admin audit log | Append-only, all admin actions logged |
| Encrypted API keys | Provider keys encrypted at rest, last-4 in UI |
| Evidence-first | Every finding requires captured proof |
| Anti-hallucination | AI claims must quote verbatim source text |

---

## 20. Environment variables

### Web app (`web/.env.local`)

| Variable | Required | Purpose |
|----------|----------|---------|
| `NEXT_PUBLIC_SUPABASE_URL` | Prod | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Prod | Supabase anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Prod | Server-only service role |
| `UPSTASH_REDIS_REST_URL` | Prod | Rate limiting |
| `UPSTASH_REDIS_REST_TOKEN` | Prod | Rate limiting |
| `QSTASH_TOKEN` | Prod | Job queue |
| `WORKER_URL` | Prod | Deep scan worker URL |
| `RAZORPAY_KEY_ID` | Prod | Payment gateway |
| `RAZORPAY_KEY_SECRET` | Prod | Payment gateway |
| `RAZORPAY_WEBHOOK_SECRET` | Prod | Webhook verification |
| `OPENROUTER_API_KEY` | Optional | AI analyst |
| `WORKER_CALLBACK_SECRET` | Prod | Worker auth |
| `CRON_SECRET` | Prod | Cron auth |
| `DEV_MODE` | Dev | Bypass backends |
| `DEV_TIER` | Dev | Preview tier UI |
| `THUGIR_AGENT_SCAN_ENABLED` | Optional | Enable agent scans |
| `THUGIR_AGENT_LLM_API_KEY` | Optional | Agent LLM key |

Full reference: `docs/internal/environment-variables.md`

---

## 21. Development setup

### Quick start (demo mode)

```bash
cd web
cp .env.example .env.local
# Set DEV_MODE=1 and DEV_TIER=deep
npm install
npm run dev
# → http://localhost:3000
```

### Full local stack

1. Create Supabase project, apply migrations
2. Set all env vars in `web/.env.local`
3. `npm install && npm run dev`
4. (Optional) Start worker: `cd worker && uvicorn main:app --port 8099`
5. (Optional) Install agent engine: `pip install -r services/thugir-agent/requirements.txt`
6. Make yourself admin:
   ```sql
   INSERT INTO admin_users (id, role) VALUES ('<your-user-id>', 'owner');
   ```

See `docs/internal/dev-setup.md` for full instructions.

---

## 22. Deployment

| Component | Platform | Root directory |
|-----------|----------|----------------|
| Web app | Vercel | `web/` |
| Worker | Render / Fly | `worker/` |
| Database | Supabase | `supabase/migrations/` |
| Agent engine | Worker host / local | `services/thugir-agent/` |

### Deploy checklist

1. Push `web/` to Vercel with all env vars
2. Deploy `worker/` with Supabase + QStash credentials
3. Set `WORKER_URL` in Vercel to worker `/run` endpoint
4. Configure Razorpay webhook → `/api/webhooks/razorpay`
5. Configure QStash to publish to `WORKER_URL`
6. Apply Supabase migrations
7. Seed patterns (optional): `supabase/seed/patterns.sql`
8. Insert admin user

---

## 23. Testing

```bash
cd web
npm run typecheck       # TypeScript compilation check
npm run test:framework  # 48 unit tests (helpers, patterns, damage)
npm run test:smoke      # End-to-end scan engine smoke test
npm run build           # Production build verification
npm run patterns        # Pattern catalog integrity
npm run agent-check     # Agent engine availability
```

---

## 24. Scripts and tooling

| Script | Command | Purpose |
|--------|---------|---------|
| `dev` | `npm run dev` | Local dev server |
| `build` | `npm run build` | Production build |
| `typecheck` | `npm run typecheck` | TypeScript check |
| `test:framework` | `npm run test:framework` | Unit tests |
| `test:smoke` | `npm run test:smoke` | Scan smoke test |
| `power-scan` | `npm run power-scan` | CLI power scan with `--agent` |
| `agent-check` | `npm run agent-check` | Check agent engine |
| `patterns` | `npm run patterns` | Regenerate catalog + seed |
| `ship-gate` | `npm run ship-gate` | CI ship gate |
| `pr-integrity` | `npm run pr-integrity` | PR integrity audit |

---

## 25. Documentation index

| Document | Path | Purpose |
|----------|------|---------|
| **Everything (this file)** | `everything.md` | Complete A–Z reference |
| **Hackathon guide** | `docs/HACKATHON_GUIDE.md` | Quick demo guide |
| **README** | `README.md` | Project overview |
| **Architecture** | `docs/internal/architecture.md` | System design |
| **Dev setup** | `docs/internal/dev-setup.md` | Local development |
| **Environment vars** | `docs/internal/environment-variables.md` | All env variables |
| **Pattern spec** | `docs/internal/pattern-library-spec.md` | Pattern authoring |
| **Admin runbook** | `docs/internal/admin-runbook.md` | Operator guide |
| **Agent engine** | `docs/internal/agent-engine.md` | Agent integration |
| **Incident response** | `docs/internal/incident-response.md` | Incident procedures |
| **Roadmap** | `docs/internal/MOAT_AND_ROADMAP.md` | Product roadmap |
| **Design rules** | `WebDesignRules.md` | UI/brand guidelines |
| **Security skills** | `docs/internal/security-skills/` | 141 WSTG/attack playbooks |
| **Pattern catalog** | `docs/internal/pattern-catalog.json` | Machine-readable catalog |

---

## 26. Roadmap

From `docs/internal/MOAT_AND_ROADMAP.md`:

- Public trust badge / verify page quality pass
- SEO "Scan your [builder] app" landing pages
- One-click share-link scans
- Analyst false-positive rejection loop
- TOTP 2FA for admin panel
- Badge SVG endpoint (`/badge/[id].svg`)
- Compare pages (`/compare/[slug]`)
- Platform checklists (`/checklists/[platform]`)

---

## Quick reference card

```
Product:     Thugir Scanner
Patterns:    133 (77 free, 56 deep)
Platforms:   9 (generic + 8 AI builders)
Scan tiers:  Free → Deep → Continuous
Tech stack:  Next.js 14, TypeScript, Python, Supabase, Razorpay
AI:          OpenRouter (analyst + deep probe + agent engine)
Demo:        DEV_MODE=1 → npm run dev → localhost:3000
Docs:        everything.md (this file)
Hackathon:   docs/HACKATHON_GUIDE.md
```

---

*Last updated: July 2026 — Thugir Labs*
