# CyberStrike reference (vendor)

Source: [CyberStrikeus/CyberStrike](https://github.com/CyberStrikeus/CyberStrike)  
License: **AGPL-3.0-only** — see `vendor/LICENSE`

## Inventory

| Library | Count | Path |
|---------|-------|------|
| OWASP WSTG 4.2 | 125 | `vendor/skills/WEB/OWASP_WSTG_4.2/` |
| Attack playbooks | 16 | `vendor/skills/attack-*/` |
| **Total skills** | **141** | `vendor/index.json` |

### Attack playbooks included

`attack-ssrf`, `attack-jwt`, `attack-idor-automation`, `attack-ssti`, `attack-graphql`,
`attack-cors`, `attack-open-redirect`, `attack-xxe`, `attack-websocket`, `attack-race-condition`,
`attack-prototype-pollution`, `attack-request-smuggling`, `attack-rate-limit-bypass`,
`attack-subdomain-takeover`, `attack-host-header`, `attack-cache-poison`

## Prompts (upstream copy)

| File | Purpose |
|------|---------|
| `vendor/prompts/common-prompt.txt` | 3-gate confirmation, lane discipline |
| `vendor/prompts/report_vulnerability.txt` | Severity triage oracle |
| `vendor/SKILL_GUIDE.md` | Skill authoring format |

## Thugir integration

| Code | Role |
|------|------|
| `web/lib/methodology/` | 3-gate, severity triage, coverage memory |
| `web/lib/methodology/skills.ts` | Load skills by id from vendor index |
| `web/lib/ai/deep-probe.ts` | Web scanner AI with triage |
| Power-loop automations | Read WSTG oracles before benchmark scans |

## Refresh from upstream

```bash
# Re-download all skills (same script as initial import)
bash docs/reference/cyberstrike/sync-skills.sh
node docs/reference/cyberstrike/build-index.mjs
```

## License note

Thugir Scanner is proprietary. AGPL vendor files must stay in `vendor/` with LICENSE intact.
Consult legal counsel before production use of AGPL-derived material.
