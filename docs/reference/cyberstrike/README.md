# CyberStrike reference (vendor)

Source: [CyberStrikeus/CyberStrike](https://github.com/CyberStrikeus/CyberStrike)  
License: **AGPL-3.0-only** — see `vendor/LICENSE`

## What we copied

| Path | Purpose |
|------|---------|
| `vendor/prompts/common-prompt.txt` | 3-gate confirmation, lane discipline, false-positive rules |
| `vendor/prompts/report_vulnerability.txt` | Bug-bounty severity triage oracle |
| `vendor/SKILL_GUIDE.md` | OWASP WSTG skill authoring format |
| `vendor/skills/wstg-*` | Sample OWASP test playbooks (SQLi, IDOR, reflected XSS) |

## How Thugir uses this

Application code in `web/lib/methodology/` **adapts** these patterns for Thugir Scanner.
Full upstream text stays in `vendor/` for attribution and AGPL compliance.

Do not delete `vendor/LICENSE`. If you modify vendor files, document changes.

## Commercial note

Thugir Scanner is proprietary. Network use of AGPL-derived code may require compliance
with AGPL obligations or a commercial license from CyberStrike (contact@cyberstrike.io).
Consult legal counsel before production deployment.

## Refresh vendor copy

```bash
BASE="https://raw.githubusercontent.com/CyberStrikeus/CyberStrike/main"
curl -sL "$BASE/packages/cyberstrike/src/agent/prompt/vuln/common-prompt.txt" \
  -o docs/reference/cyberstrike/vendor/prompts/common-prompt.txt
```
