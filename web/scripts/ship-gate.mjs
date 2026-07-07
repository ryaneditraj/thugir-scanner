#!/usr/bin/env node
/**
 * Pre-ship gate for power-loop → main promotion.
 * Usage: node web/scripts/ship-gate.mjs
 * Exit 0 = safe to merge. Exit 1 = blocked.
 */
import { execSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dir, "../..");

const SACRED = [
  "web/lib/razorpay/",
  "web/app/api/billing/",
  "web/app/api/webhooks/razorpay/",
  "web/components/UpgradePanel.tsx"
];

function sh(cmd) {
  return execSync(cmd, { cwd: ROOT, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
}

function main() {
  const report = { ok: true, checks: [], blockers: [] };

  try {
    sh("git fetch origin main");
  } catch {
    report.blockers.push("git fetch origin main failed");
    report.ok = false;
  }

  let diffFiles = [];
  try {
    diffFiles = sh("git diff --name-only origin/main...HEAD").split("\n").filter(Boolean);
  } catch {
    report.blockers.push("could not diff against origin/main");
    report.ok = false;
  }

  for (const f of diffFiles) {
    for (const s of SACRED) {
      if (f.startsWith(s) || f === s.replace(/\/$/, "")) {
        report.blockers.push(`sacred zone touched: ${f}`);
        report.ok = false;
      }
    }
  }
  report.checks.push({ name: "sacred_zone", files_in_diff: diffFiles.length, blocked: report.blockers.filter((b) => b.includes("sacred")) });

  try {
    sh("cd web && npm run typecheck");
    report.checks.push({ name: "typecheck", status: "pass" });
  } catch (e) {
    report.blockers.push("typecheck failed");
    report.ok = false;
    report.checks.push({ name: "typecheck", status: "fail" });
  }

  const scorePath = resolve(ROOT, "docs/internal/power-loop/scoreboard.json");
  if (existsSync(scorePath)) {
    const score = JSON.parse(readFileSync(scorePath, "utf8"));
    report.checks.push({
      name: "scoreboard",
      improvements_shipped: score.improvements_shipped ?? 0,
      total_findings: score.total_findings ?? 0
    });
  }

  console.log(JSON.stringify(report, null, 2));
  process.exit(report.ok ? 0 : 1);
}

main();
