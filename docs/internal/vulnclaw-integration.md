# VulnClaw integration (Thugir Scanner)

VulnClaw is vendored at `services/vulnclaw/` as the **AI agent penetration engine**.
It adds goal-driven OODA solving, MCP tools, 21 pentest skills, traffic evidence, and
structured reports on top of Thugir's pattern-based scanner.

**Upstream:** https://github.com/Unclecheng-li/VulnClaw (MIT)

## Architecture

```
Thugir Scanner (Next.js / TypeScript)
├── web/lib/checks/          ← fast pattern + rule engine (Vercel)
├── web/lib/vulnclaw/        ← TypeScript bridge
└── services/vulnclaw/       ← full VulnClaw Python agent (local/worker)
    ├── vulnclaw/            ← agent, solver, MCP, skills, traffic, reports
    └── thugir_runner.py     ← JSON stdin/stdout bridge
```

| Layer | Where it runs | Power |
|-------|---------------|-------|
| Free scan | Vercel | Pattern library + rules |
| Deep scan | Vercel | + crawl + AI deep probe |
| **Agent scan** | Python host | + VulnClaw solver, tools, skills |

## Setup (one time)

```bash
# Python 3.10+
pip install -r services/vulnclaw/requirements.txt

# LLM credentials
export VULNCLAW_LLM_API_KEY=sk-...
export VULNCLAW_LLM_BASE_URL=https://api.openai.com/v1
export VULNCLAW_LLM_MODEL=gpt-4o

# Verify
cd web && npm run vulnclaw-check
```

## Usage

### Power Scan (automations)

```bash
cd web && npm run power-scan -- --benchmarks --vulnclaw
cd web && npm run power-scan -- --benchmarks --vulnclaw --vulnclaw-deep
```

### API (dev / worker)

```bash
# Enable on non-Vercel worker
export THUGIR_AGENT_SCAN_ENABLED=1

curl -X POST http://localhost:3000/api/scan/agent \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://juice-shop.herokuapp.com","scan_mode":"quick"}'
```

### Standalone VulnClaw CLI

```bash
cd services/vulnclaw
PYTHONPATH=. python -m vulnclaw.cli.main run https://target.example.com --non-interactive
PYTHONPATH=. python -m vulnclaw.cli.main web   # Web UI on :7788
```

## Skills

- **Thugir WSTG oracles:** `docs/internal/security-skills/` (141 playbooks)
- **VulnClaw pentest skills:** `services/vulnclaw/vulnclaw/skills/` (21 skills, 180 refs)

Loader: `web/lib/methodology/skills.ts` — `loadVulnClawSkill()`, `loadVulnClawOracleSummaries()`

## Methodology ports

| VulnClaw | Thugir |
|----------|--------|
| Evidence anti-hallucination gate | `web/lib/methodology/evidence-gate.ts` |
| 3-gate exploit confirmation | `web/lib/methodology/three-gate.ts` |
| Blackboard Fact/Intent solver | VulnClaw Python (full fidelity) |

## Sacred zone

Agent automations must **never** modify Razorpay/billing files. See `ship-gate.mjs`.

## Vercel note

Agent scans require Python and cannot run in serverless functions. Use:
- Local `power-scan --vulnclaw`
- Cursor automations on a cloud agent with Python
- Optional Docker worker (`services/vulnclaw/docker-compose.yml`)
