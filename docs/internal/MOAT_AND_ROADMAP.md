# Thugir Scanner — Moat & Execution Roadmap

**Product:** Security scanner for AI-built ("vibe-coded") apps  
**North star:** The default security check founders run before they share a Lovable / Bolt / v0 / Replit / Cursor-built URL.  
**Owner:** Engineering (CTO execution track)  
**Status:** Active — execute in order; do not re-plan weekly.

---

## 1. What "best on the planet" means (measurable)

| Metric | Target | Why it matters |
|--------|--------|----------------|
| **True-positive rate on free scan** | ≥90% of shown findings are real | Trust is the product |
| **Vibe-stack coverage** | Patterns for every major builder + backend | Moat = data, not UI |
| **Time to first verified finding** | <30s free, <5m deep | Founders abandon slow tools |
| **Fix-prompt usefulness** | Every finding has a paste-back prompt | We close the loop in Cursor/Claude |
| **FP rate (critical/high)** | <5% after evidence gate | Noise kills conversion |
| **Pattern ship velocity** | New patterns as **data** (DB row), not deploys | Competitors can't keep up |

We do **not** win by scanning more of the internet. We win by knowing **exactly** what AI scaffolds ship wrong, proving it with evidence, and handing the founder a fix they can paste into their AI editor.

---

## 2. The moat (defendable advantages)

```
Scanners find CVEs.  Thugir finds what vibe-coding ships by default.
```

| Moat layer | What we own | Competitor gap |
|------------|-------------|----------------|
| **1. Pattern IP** | Curated library of AI-builder misconfigs (Supabase RLS, service_role in bundle, VITE_ secret prefix, .env/.git, builder fingerprints) | Generic scanners don't encode Lovable/Bolt/v0 defaults |
| **2. Evidence gate** | No finding without captured proof; free tier never receives gated fields | Marketing scanners invent "issues" |
| **3. Fix prompts** | Every pattern ships a paste-back prompt for Cursor/Claude/Copilot | Reports without action |
| **4. Tiered blur** | Free proves value; Deep unlocks structural checks; Continuous monitors | All-or-nothing pricing |
| **5. Engine reuse** | Deep Scan rides `thugir-node` max-power (probes, BOLA, sqlmap) without forking the research platform | Startups rebuild engines |
| **6. Operator trust** | Admin audit log, ownership attestation, SSRF blocks, Razorpay signature verify | Weak ops = enterprise no |

**Moat test:** If a competitor clones our UI in a weekend, do they still lack our pattern library + evidence discipline + fix prompts? If yes, moat holds.

---

## 3. Execution list (do in order)

### Phase A — Pattern supremacy (NOW)
- [x] Core secrets (OpenAI, Stripe, AWS, Supabase service_role, GitHub, …)
- [x] Generic exposure (.env, .git, source maps, headers)
- [x] Supabase RLS + service_role
- [x] Firebase, Lovable, Bolt, v0 seeds
- [x] **Replit / Cursor / Windsurf / Vercel-stack patterns**
- [x] Neon / DB URL / public-env stack patterns (Clerk covered via public-prefix + Stripe-class keys)
- [x] Pattern catalog auto-generated (`npm run patterns`)
- [x] Seed SQL stays in sync with `STATIC_PATTERNS` (`npm run patterns`)
- [x] Per-builder SEO pages (`/platforms/[platform]`)
- [x] Per-pattern SEO pages (`/vulnerabilities/[slug]`)

### Phase B — Proof supremacy
- [x] Evidence gate + serializeFindings blur
- [x] Free min-confidence threshold
- [x] Deep worker uses TCSF max-power
- [x] Continuous: `monitors` table + `/api/monitors` API (scheduler worker still TODO)
- [x] Continuous: cron/QStash tick to enqueue due monitors + delta email
- [ ] Public badge / verify page quality pass

### Phase C — Distribution
- [x] Marketing site + free scan form
- [x] Account dashboard + upgrade (Razorpay)
- [x] Admin console + health
- [ ] SEO pages per builder ("Scan your Lovable app")
- [ ] One-click "scan this URL" from share links

### Phase D — Learning loop
- [ ] Analyst FP rejection → pattern disable / tighten regex
- [ ] Trajectory of which patterns convert free→paid
- [ ] Quarterly pattern review (retire noisy, promote high-yield)

---

## 4. Non-goals (protect focus)

- Not a general pentest platform (that's `thugir-node` / TCSF)
- Not a CVE database UI
- Not authenticated multi-tenant SaaS red-team without ownership proof
- Not replacing EDR/SIEM

---

## 5. Weekly rhythm

| Day | Action |
|-----|--------|
| Mon | Pick 1–2 items from current phase |
| Daily | `smoke_stack.sh` + free/deep-run smoke |
| Fri | Update pattern count in this doc + MISSION if needed |

---

## 6. How to run / verify

```bash
# Platform deep scan (full power)
cd thugir-node && bash run_nexus.sh   # :8080/workspace

# Commercial scanner (local)
cd web && DEV_MODE=1 DEV_TIER=deep npm run dev   # :3000

# Gates
cd thugir-node && .venv/bin/python tools/run_finding_depth_gate.py
cd web && npm run typecheck && node scripts/pattern-catalog.mjs

# Health (prod credentials only when not demo placeholders)
curl -s http://localhost:3000/api/health
```

**Production checklist:** real Supabase + migrations `0001`–`0004`, Razorpay keys + webhook → `/api/webhooks/razorpay`, `WORKER_URL` + QStash for queued Deep Scans.

---

## 7. Pattern count (update when library grows)

Run `node web/scripts/pattern-catalog.mjs` — writes `docs/internal/pattern-catalog.json`.

---

## 8. Decision log (short)

| Decision | Rationale |
|----------|-----------|
| Patterns as data + static seed | Ship new checks without waiting on deploys |
| Free = high-confidence only | Trust compounds; FPs destroy it |
| Deep = worker + max-power | Structural vulns need active probes |
| Fix prompts mandatory | Founders live in AI editors |
| Separate `app/` from `thugir-node` | Product surface ≠ research platform |
