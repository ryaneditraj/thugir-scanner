#!/usr/bin/env node
/**
 * Emit pattern catalog stats (moat inventory).
 * Run: node scripts/pattern-catalog.mjs
 */
import { writeFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

// Patterns are TypeScript — load via a tiny inline inventory by parsing slug: lines.
// Keeps the script free of a TS build step.
import { readFileSync, readdirSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const patternsDir = join(__dirname, "../lib/patterns");
const outPath = join(__dirname, "../../docs/internal/pattern-catalog.json");

const files = readdirSync(patternsDir).filter((f) => f.endsWith(".ts") && f !== "types.ts" && f !== "index.ts");
const byPlatform = {};
const byTier = { free: 0, deep: 0, continuous: 0 };
const byCategory = {};
const slugs = [];

for (const file of files) {
  const text = readFileSync(join(patternsDir, file), "utf8");
  // Match pattern object fields in order-ish blocks
  const blocks = text.split(/slug:\s*"/).slice(1);
  for (const block of blocks) {
    const slug = block.match(/^([^"]+)"/)?.[1];
    if (!slug) continue;
    const platform = block.match(/platform:\s*"([^"]+)"/)?.[1] || "generic";
    const tier = block.match(/tierRequired:\s*"([^"]+)"/)?.[1] || "free";
    const category = block.match(/category:\s*"([^"]+)"/)?.[1] || "general";
    const enabled = !/enabled:\s*false/.test(block.slice(0, 400));
    if (!enabled) continue;
    slugs.push(slug);
    byPlatform[platform] = (byPlatform[platform] || 0) + 1;
    byTier[tier] = (byTier[tier] || 0) + 1;
    byCategory[category] = (byCategory[category] || 0) + 1;
  }
}

// SECRET_DEFS in secrets.ts use a different shape — count via map output slug:
const secretsText = readFileSync(join(patternsDir, "secrets.ts"), "utf8");
const secretSlugs = [...secretsText.matchAll(/slug:\s*"([^"]+)"/g)].map((m) => m[1]);
// secrets already counted if we split on slug — secrets.ts uses slug in SECRET_DEFS

const catalog = {
  generatedAt: new Date().toISOString(),
  total: slugs.length,
  uniqueSlugs: [...new Set(slugs)].length,
  byPlatform,
  byTier,
  byCategory,
  slugs: [...new Set(slugs)].sort(),
  moatNote:
    "Pattern library is product IP: AI-builder misconfigs with evidence + fix prompts, not a CVE dump."
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(catalog, null, 2) + "\n");
console.log(JSON.stringify({ total: catalog.total, byPlatform, byTier }, null, 2));
console.log("Wrote", outPath);
