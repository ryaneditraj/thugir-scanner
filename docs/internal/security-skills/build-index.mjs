#!/usr/bin/env node
/**
 * Build search index for Thugir security skills library.
 * Usage: node docs/internal/security-skills/build-index.mjs
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const __dir = dirname(fileURLToPath(import.meta.url));
const skillsRoot = join(__dir, "skills");

function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, acc);
    else if (name === "SKILL.md") acc.push(p);
  }
  return acc;
}

function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---/);
  if (!m) return {};
  const fm = {};
  for (const line of m[1].split("\n")) {
    const kv = line.match(/^(\w+):\s*(.+)$/);
    if (kv) fm[kv[1]] = kv[2].replace(/^["']|["']$/g, "");
  }
  return fm;
}

const entries = [];
for (const file of walk(skillsRoot)) {
  const text = readFileSync(file, "utf8");
  const fm = parseFrontmatter(text);
  const rel = relative(__dir, file);
  const dir = dirname(rel);
  const id = fm.name || dir.split("/").pop();
  entries.push({
    id,
    path: rel,
    name: fm.name || id,
    description: fm.description || "",
    category: fm.category || "",
    owasp_id: fm.owasp_id || "",
    tags: fm.tags || ""
  });
}

entries.sort((a, b) => a.id.localeCompare(b.id));
const index = {
  generated_at: new Date().toISOString(),
  owner: "Thugir Labs",
  count: entries.length,
  entries
};

writeFileSync(join(__dir, "index.json"), JSON.stringify(index, null, 2));
console.log(JSON.stringify({ count: entries.length, path: "index.json" }));
