# Thugir Security Skills Library

Internal playbook library for web application security testing. Used by power-loop automations and the scanner methodology engine.

## Inventory

| Library | Count | Path |
|---------|-------|------|
| OWASP WSTG 4.2 | 125 | `skills/WEB/OWASP_WSTG_4.2/` |
| Attack playbooks | 16 | `skills/attack-*/` |
| **Total** | **141** | `index.json` |

## Prompts

| File | Purpose |
|------|---------|
| `prompts/common-prompt.txt` | 3-gate confirmation, lane discipline |
| `prompts/report_vulnerability.txt` | Severity triage oracle |

## Integration

| Code | Role |
|------|---------|
| `web/lib/methodology/` | 3-gate, severity triage, coverage memory |
| `web/lib/methodology/skills.ts` | Load skills by id |
| Power-loop automations | Read oracles before benchmark scans |

## Rebuild index

```bash
node docs/internal/security-skills/build-index.mjs
```
