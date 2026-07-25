# Thugir Agent Engine

The **Thugir Agent Engine** lives at `services/thugir-agent/` and provides goal-driven
AI penetration testing on top of Thugir's pattern-based scanner. It adds OODA-loop solving,
MCP tools, pentest skills, traffic evidence capture, and structured reports.

## Architecture

```
Thugir Scanner (Next.js / TypeScript)
├── web/lib/checks/          ← fast pattern + rule engine (Vercel)
├── web/lib/agent/           ← TypeScript bridge
└── services/thugir-agent/   ← Python agent engine (local/worker)
    └── thugir_runner.py     ← JSON stdin/stdout bridge
```

| Layer | Where it runs | Power |
|-------|---------------|-------|
| Free scan | Vercel | Pattern library + rules |
| Deep scan | Vercel | + crawl + AI deep probe |
| **Agent scan** | Python host | + Thugir Agent Engine solver, tools, skills |

## Setup (one time)

```bash
# Python 3.10+
pip install -r services/thugir-agent/requirements.txt

# LLM credentials
export THUGIR_AGENT_LLM_API_KEY=sk-...
export THUGIR_AGENT_LLM_BASE_URL=https://api.openai.com/v1
export THUGIR_AGENT_LLM_MODEL=gpt-4o

# Verify
cd web && npm run agent-check
```

## Usage

### Power Scan (automations)

```bash
cd web && npm run power-scan -- --benchmarks --agent
cd web && npm run power-scan -- --benchmarks --agent --agent-deep
```

### API (dev / worker)

```bash
# Enable on worker or local dev
export THUGIR_AGENT_SCAN_ENABLED=1

curl -X POST http://localhost:3000/api/scan/agent \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","scan_mode":"quick"}'
```

### Native TypeScript power rules (always on)

These run inside the main scan engine without Python:

- `thugirJwtClaims` — weak JWT alg/claims in client bundles (free tier)
- `thugirJsEndpoints` — sensitive API paths in shipped JS (free tier)
- `thugirDirEnum` — directory probing for actuator/swagger/.git (deep tier)
- `reflexionEscalatedXss/Sqli/Ssti` — WAF-bypass encoding escalation (deep tier)

## Methodology modules

| Module | Path | Purpose |
|--------|------|---------|
| Reflexion | `web/lib/methodology/reflexion.ts` | L0–L4 payload escalation when probes are blocked |
| Blackboard | `web/lib/methodology/blackboard.ts` | Fact/intent tracking to prevent probe loops |
| Evidence gate | `web/lib/methodology/evidence-gate.ts` | Anti-hallucination — claims need verbatim proof |
| Skills | `web/lib/methodology/skills.ts` | 141 WSTG/attack playbooks + agent oracle skills |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `THUGIR_AGENT_SCAN_ENABLED` | `1` to allow agent scans in production worker |
| `THUGIR_AGENT_SCAN_MODE` | `quick` or `deep` default for enrich pipeline |
| `THUGIR_AGENT_PYTHON` | Path to Python binary |
| `THUGIR_AGENT_LLM_API_KEY` | LLM API key for agent |
| `THUGIR_AGENT_LLM_BASE_URL` | LLM API base URL |
| `THUGIR_AGENT_LLM_MODEL` | Model name |
| `THUGIR_AGENT_LLM_PROVIDER` | Provider id (default `openai`) |
