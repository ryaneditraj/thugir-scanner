# Thugir — Hackathon Demo Guide

Quick reference for running and presenting Thugir Scanner at a hackathon.

## 30-second pitch

**Thugir** is a security scanner built for AI-generated web apps. It finds exposed secrets,
open databases, broken access control, and injection flaws — with captured evidence for every
finding. Free scans run instantly; Deep Scans crawl the full app with 133 detection patterns.

## Demo setup (no backend required)

```bash
cd web
cp .env.example .env.local
```

Edit `.env.local` (or copy the pre-filled hackathon file):

```bash
cp web/config/hackathon.env web/.env.local
```

Or edit `.env.local` manually:

```env
DEV_MODE=1
DEV_TIER=deep
NEXT_PUBLIC_SITE_URL=http://localhost:3000
HACK_CLUB_AI_API_KEY=sk-hc-v1-...   # already in config/hackathon.env
```

**Change the AI model:** `/admin/settings` → AI models & keys → edit **Model** per tier (default `qwen/qwen3-32b`). Click **Test AI** before saving.

```bash
npm install
npm run dev
```

Open **http://localhost:3000**

## Demo flow (5 minutes)

### 1. Landing page — Free scan (30 sec)

- Enter **`petstore.swagger.io`** (primary live URL — 4 findings, no criticals, fast)
- Backup URLs if conference Wi‑Fi blocks it: **`httpbin.org`** (5 findings) or **`example.com`** (1 finding, boring but always works)
- Click **Scan now**
- Show findings with severity, impact, and evidence
- Scroll to the **sealed Deep Scan** block — dashed border, blur cards, big lock (readable from 10 ft on a projector)

**Offline fallback:** if live scan fails, say "conference Wi‑Fi" and jump to `/demo` immediately.

### 1b. Verify badge (20 sec) — highest-leverage trust demo

- Visit **`/verify/demo`** — white trust seal card, big pass/attention status
- One line for judges: *"Anyone can verify a scan passed without seeing private findings."*
- In production, share **`/verify/<scan-id>`** after a real Deep Scan completes

### 2. Static demo report (30 sec)

- Visit **/demo** — pre-built sample report with realistic findings
- Visit **/report/sample** — redacted Deep Scan sample

### 3. Dashboard (1 min)

- Go to **/dashboard** (auth bypassed in DEV_MODE)
- Show **App URL scan** and **GitHub code scan** tabs
- Run a Deep Scan inline (works in dev via `/api/scan/deep-run`)
- Show tier badge, upgrade panel, scan history

### 4. Admin panel (1 min)

- Go to **/admin**
- Show health dashboard: Supabase, Razorpay, Worker, AI analyst, Agent engine
- Visit **/admin/patterns** — 133 detection patterns, CRUD
- Visit **/admin/scans** — scan management
- Visit **/admin/settings** — platform configuration

### 5. Technical depth (2 min)

Highlight these differentiators:

| Feature | What to say |
|---------|-------------|
| **133 patterns** | Data-driven detection library — add patterns without code deploys |
| **Evidence-first** | Every finding requires captured proof, not guesses |
| **AI analyst** | Tailored fix prompts and max-damage business impact per finding |
| **Reflexion probes** | WAF-bypass encoding escalation (L0–L4) for XSS/SQLi/SSTI |
| **Agent engine** | Optional Python AI pentester for autonomous deep testing |
| **Tier gating** | Server-side blur — gated data never reaches the client DOM |

## Pages to show

| URL | Purpose |
|-----|---------|
| `/` | Landing + free scan |
| `/verify/demo` | Public trust badge (projector-friendly) |
| `/how-scans-work` | Methodology explainer |
| `/demo` | Sample report |
| `/dashboard` | User portal |
| `/admin` | Operator console |
| `/admin/patterns` | Pattern library |
| `/vulnerabilities/secret-stripe-live` | SEO vulnerability page |
| `/platforms/lovable` | Platform-specific landing |

## Verification commands

```bash
cd web
npm run typecheck          # TypeScript check
npm run test:framework     # 48 unit tests
npm run test:smoke         # Scan engine smoke test
npm run patterns           # List 133 patterns
npm run agent-check        # Check Python agent availability
npm run build              # Production build
```

## Full production setup

For judges who want to see the real stack:

1. **Supabase** — auth + Postgres (migrations in `supabase/migrations/`)
2. **Razorpay** — Deep Scan payments (test keys fine)
3. **Upstash** — rate limiting + QStash job queue
4. **Worker** — Python Deep Scan executor (`worker/`)
5. **Agent engine** — optional Python AI layer (`services/thugir-agent/`)

See [everything.md](../everything.md) for the complete A–Z reference.

## Pre-stage checklist (run twice tonight)

1. **Env:** `DEV_MODE=1` and `DEV_TIER=deep` in `web/.env.local` — without this, `/api/scan/free` returns 500.
2. **Live scan:** `petstore.swagger.io` from `/` — confirm 3–4 findings + sealed block at bottom.
3. **Projector test:** Can you read severity pills, finding titles, and "The deeper report is sealed" from 10 feet?
4. **Verify badge:** Open `/verify/demo` — seal, domain, and "Passed" pill should be obvious at a glance.
5. **Full flow:** `/` → `/verify/demo` → `/demo` → `/dashboard` → `/admin/patterns` — twice, on conference Wi‑Fi if possible.
6. **Kill switch:** If live scan hangs >15s, say "conference Wi‑Fi" and open `/demo` — never stall on stage.

## Talking points

- Built for the **AI-builder era** — detects misconfigs that Lovable, Bolt, v0, and similar tools ship by default
- **Commercial-ready** — multi-tenant auth, billing, admin panel, audit log, RLS
- **Pattern library is the IP** — 133 patterns across 9 platforms, extensible as data
- **Three scan tiers** — Free (instant), Deep (crawl + full library), Continuous (monitors)
- **Safety by design** — SSRF guard, domain ownership verification, server-side tier gating
