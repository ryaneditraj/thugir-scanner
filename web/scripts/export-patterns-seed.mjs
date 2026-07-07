#!/usr/bin/env node
/**
 * Regenerate supabase/seed/patterns.sql from TypeScript pattern sources.
 * Run: node scripts/export-patterns-seed.mjs
 */
import { readFileSync, writeFileSync, readdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const patternsDir = join(__dirname, "../lib/patterns");
const outPath = join(__dirname, "../../supabase/seed/patterns.sql");

function extractStringField(block, field) {
  const re = new RegExp(`${field}:\\s*"((?:\\\\.|[^"\\\\])*)"`, "s");
  const m = block.match(re);
  if (m) return m[1].replace(/\\n/g, "\n").replace(/\\"/g, '"');
  // template-ish multi-line with backticks not used; try single-quoted no
  return null;
}

function extractObjectField(block, field) {
  const start = block.indexOf(`${field}:`);
  if (start < 0) return null;
  const brace = block.indexOf("{", start);
  if (brace < 0) return null;
  let depth = 0;
  for (let i = brace; i < block.length; i++) {
    if (block[i] === "{") depth++;
    else if (block[i] === "}") {
      depth--;
      if (depth === 0) {
        const raw = block.slice(brace, i + 1);
        // convert TS object-ish to JSON-ish
        let jsonish = raw
          .replace(/(\w+)\s*:/g, '"$1":')
          .replace(/'/g, '"')
          .replace(/,\s*}/g, "}")
          .replace(/,\s*]/g, "]");
        try {
          return JSON.parse(jsonish);
        } catch {
          return { _raw: raw.replace(/\s+/g, " ").slice(0, 500) };
        }
      }
    }
  }
  return null;
}

function sqlEscape(s) {
  return String(s ?? "").replace(/'/g, "''");
}

function sqlJson(obj) {
  return sqlEscape(JSON.stringify(obj ?? {}));
}

const files = readdirSync(patternsDir).filter(
  (f) => f.endsWith(".ts") && f !== "types.ts" && f !== "index.ts"
);

const patterns = [];

// secrets.ts uses SECRET_DEFS shape, not full Pattern objects.
function loadSecrets() {
  const text = readFileSync(join(patternsDir, "secrets.ts"), "utf8");
  const blocks = text.split(/slug:\s*"/).slice(1);
  for (const block of blocks) {
    const slug = block.match(/^([^"]+)"/)?.[1];
    if (!slug || !slug.startsWith("secret-")) continue;
    const name = extractStringField(block, "name") || slug;
    const severity = extractStringField(block, "severity") || "high";
    const impact = extractStringField(block, "impact") || name;
    const regex = extractStringField(block, "regex") || "";
    const validate = extractStringField(block, "validate");
    patterns.push({
      slug,
      platform: "generic",
      category: "Exposed secret",
      severity,
      title: `${name} exposed in client bundle`,
      description: `A ${name} was found in JavaScript or HTML served to the browser.`,
      impact,
      detectorKind: "secret_regex",
      detectorConfig: {
        regex,
        ...(validate ? { validate } : {}),
        secretName: name,
        serverOnly: true
      },
      tier: "free",
      fixPrompt: `A ${name} is exposed in my client bundle. Remove it from all client-side code and client-exposed environment variables, move every use of it into server-side code, and tell me exactly which files referenced it so I can rotate and confirm.`,
      remediation: {
        summary: `Rotate the ${name} now and move it server-side.`,
        steps: [
          "Treat the key as compromised and rotate it with the provider immediately.",
          "Remove it from all client code and from any client-exposed env var (e.g. NEXT_PUBLIC_*, VITE_*).",
          "Access the key only from server-side code (route handlers / serverless functions)."
        ]
      }
    });
  }
}

loadSecrets();

for (const file of files) {
  if (file === "secrets.ts") continue;
  const text = readFileSync(join(patternsDir, file), "utf8");
  const blocks = text.split(/slug:\s*"/).slice(1);
  for (const block of blocks) {
    const slug = block.match(/^([^"]+)"/)?.[1];
    if (!slug) continue;
    if (/enabled:\s*false/.test(block.slice(0, 800))) continue;
    const platform = extractStringField(block, "platform") || "generic";
    const category = extractStringField(block, "category") || "general";
    const severity = extractStringField(block, "severityDefault") || "info";
    const title = extractStringField(block, "title") || slug;
    const description = extractStringField(block, "description") || title;
    const impact = extractStringField(block, "impactOneline") || title;
    const detectorKind = extractStringField(block, "detectorKind") || "http_probe";
    const tier = extractStringField(block, "tierRequired") || "free";
    const fixPrompt = extractStringField(block, "fixPrompt") || "";
    const detectorConfig = extractObjectField(block, "detectorConfig") || {};
    const remediation = extractObjectField(block, "remediation");
    patterns.push({
      slug,
      platform,
      category,
      severity,
      title,
      description,
      impact,
      detectorKind,
      detectorConfig,
      tier,
      fixPrompt,
      remediation
    });
  }
}

// Deduplicate by slug (last wins)
const bySlug = new Map();
for (const p of patterns) bySlug.set(p.slug, p);
const unique = [...bySlug.values()].sort((a, b) => a.slug.localeCompare(b.slug));

const lines = [
  "-- AUTO-GENERATED from web/lib/patterns — do not edit by hand.",
  "-- Regenerate: cd app/web && node scripts/export-patterns-seed.mjs",
  "",
  "insert into patterns (",
  "  slug, platform, category, severity_default, title, description, impact_oneline,",
  "  detector_kind, detector_config, tier_required, remediation_json, fix_prompt, enabled",
  ")",
  "values"
];

const values = unique.map((p, i) => {
  const rem = p.remediation ? `'${sqlJson(p.remediation)}'::jsonb` : "null";
  const row = `  ('${sqlEscape(p.slug)}', '${sqlEscape(p.platform)}', '${sqlEscape(p.category)}', '${sqlEscape(p.severity)}',
   '${sqlEscape(p.title)}',
   '${sqlEscape(p.description)}',
   '${sqlEscape(p.impact)}',
   '${sqlEscape(p.detectorKind)}',
   '${sqlJson(p.detectorConfig)}'::jsonb,
   '${sqlEscape(p.tier)}',
   ${rem},
   '${sqlEscape(p.fixPrompt)}',
   true)`;
  return row + (i < unique.length - 1 ? "," : "");
});

lines.push(...values);
lines.push(
  "on conflict (slug) do update set",
  "  platform = excluded.platform,",
  "  category = excluded.category,",
  "  severity_default = excluded.severity_default,",
  "  title = excluded.title,",
  "  description = excluded.description,",
  "  impact_oneline = excluded.impact_oneline,",
  "  detector_kind = excluded.detector_kind,",
  "  detector_config = excluded.detector_config,",
  "  tier_required = excluded.tier_required,",
  "  remediation_json = excluded.remediation_json,",
  "  fix_prompt = excluded.fix_prompt,",
  "  enabled = excluded.enabled,",
  "  updated_at = now();",
  ""
);

writeFileSync(outPath, lines.join("\n"));
console.log(`Wrote ${unique.length} patterns → ${outPath}`);
