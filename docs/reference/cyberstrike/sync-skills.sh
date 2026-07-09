#!/usr/bin/env bash
# Re-sync all CyberStrike WSTG + attack skills from upstream.
set -euo pipefail
BASE="https://raw.githubusercontent.com/CyberStrikeus/CyberStrike/main"
ROOT="$(cd "$(dirname "$0")/vendor/skills" && pwd)"

curl -sL "https://api.github.com/repos/CyberStrikeus/CyberStrike/git/trees/main?recursive=1" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('tree',[]):
    p=t['path']
    if ('OWASP_WSTG_4.2' in p or '/skill/attack-' in p) and p.endswith('SKILL.md'):
        print(p)
" | while IFS= read -r path; do
  rel="${path#.cyberstrike/skill/}"
  dest="$ROOT/$rel"
  mkdir -p "$(dirname "$dest")"
  curl -sfL "$BASE/$path" -o "$dest"
done

echo "Synced $(find "$ROOT" -name SKILL.md | wc -l) skills"
