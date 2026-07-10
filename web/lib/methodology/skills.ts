/**
 * Load Thugir security skills (WSTG + attack playbooks) by id.
 */
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dir = dirname(fileURLToPath(import.meta.url));
const REF = join(__dir, "../../../docs/internal/security-skills");
const AGENT_SKILLS = join(__dir, "../../../services/thugir-agent/vulnclaw/skills");

interface SkillIndexEntry {
  id: string;
  path: string;
  name: string;
  description: string;
  category: string;
  owasp_id: string;
}

interface SkillIndex {
  count: number;
  entries: SkillIndexEntry[];
}

let _index: SkillIndex | null = null;

function loadIndex(): SkillIndex {
  if (_index) return _index;
  const p = join(REF, "index.json");
  if (!existsSync(p)) return { count: 0, entries: [] };
  _index = JSON.parse(readFileSync(p, "utf8")) as SkillIndex;
  return _index;
}

/** Load full SKILL.md text by id (e.g. wstg-inpv-05, attack-ssrf). */
export function loadSkill(id: string): string | null {
  const entry = loadIndex().entries.find((e) => e.id === id);
  if (!entry) return null;
  const p = join(REF, entry.path);
  if (!existsSync(p)) return null;
  return readFileSync(p, "utf8");
}

/** Search skills by keyword in id, description, category, owasp_id. */
export function searchSkills(query: string, limit = 10): SkillIndexEntry[] {
  const q = query.toLowerCase();
  return loadIndex()
    .entries.filter(
      (e) =>
        e.id.includes(q) ||
        e.description.toLowerCase().includes(q) ||
        e.category.toLowerCase().includes(q) ||
        e.owasp_id.toLowerCase().includes(q)
    )
    .slice(0, limit);
}

/** Thugir Agent Engine pentest skills (recon, exploitation, playbooks). */
export const AGENT_ORACLE_SKILLS = [
  "core/recon",
  "core/vuln-discovery",
  "core/exploitation",
  "core/waf-bypass",
  "specialized/ctf-web/SKILL",
  "specialized/pentest-tools/SKILL"
] as const;

/** Load an agent skill markdown by relative path under the agent skills tree. */
export function loadAgentSkill(relativePath: string): string | null {
  const normalized = relativePath.replace(/^\/+/, "");
  const p = join(AGENT_SKILLS, normalized.endsWith(".md") ? normalized : `${normalized}.md`);
  if (!existsSync(p)) return null;
  return readFileSync(p, "utf8");
}

export function loadAgentOracleSummaries(maxCharsPerSkill = 3500): string {
  const parts: string[] = [];
  for (const rel of AGENT_ORACLE_SKILLS) {
    const text = loadAgentSkill(rel);
    if (!text) continue;
    parts.push(`### thugir-agent:${rel}\n${text.slice(0, maxCharsPerSkill)}`);
  }
  return parts.join("\n\n");
}

/** Core web oracle set for benchmark / power-loop runs. */
export const CORE_ORACLE_SKILLS = [
  "wstg-inpv-05", // SQLi
  "wstg-inpv-01", // reflected XSS
  "wstg-authz-02", // IDOR
  "wstg-apit-01", // API recon
  "attack-ssrf",
  "attack-jwt",
  "attack-idor-automation",
  "attack-ssti"
] as const;

export function loadCoreOracleSummaries(maxCharsPerSkill = 4000): string {
  const parts: string[] = [];
  for (const id of CORE_ORACLE_SKILLS) {
    const text = loadSkill(id);
    if (!text) continue;
    parts.push(`### ${id}\n${text.slice(0, maxCharsPerSkill)}`);
  }
  return parts.join("\n\n");
}

export function skillCount(): number {
  return loadIndex().count;
}
