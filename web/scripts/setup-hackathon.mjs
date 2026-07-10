#!/usr/bin/env node
/**
 * Hackathon / local demo bootstrap.
 * Copies web/config/hackathon.env → .env.local when missing so `npm run dev` works with no manual env editing.
 */
import { copyFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "config", "hackathon.env");
const dest = join(root, ".env.local");

if (!existsSync(src)) {
  console.error("Missing", src);
  process.exit(1);
}

if (existsSync(dest) && !process.argv.includes("--force")) {
  console.log("✓ .env.local already exists — skipping (use --force to overwrite from config/hackathon.env)");
} else {
  copyFileSync(src, dest);
  console.log("✓ Wrote .env.local from config/hackathon.env");
}

console.log("");
console.log("  DEV_MODE=1 · Hack Club AI · Deep tier unlocked");
console.log("  Next: npm run dev  →  http://localhost:3000");
console.log("  Demo: /  ·  /verify/demo  ·  /admin/settings");
console.log("");
