#!/usr/bin/env node
/**
 * Close open PRs whose head branches are deleted or whose patterns shipped to main.
 * Requires a GitHub token with pull_request:write (run locally — cloud agent token lacks this).
 *
 * Usage:
 *   node scripts/close-orphan-prs.mjs --dry-run
 *   node scripts/close-orphan-prs.mjs --close
 */
import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "../..");
const backlogPath = join(repoRoot, "docs/AUTOMATION_BACKLOG.md");

const args = new Set(process.argv.slice(2));
const dryRun = args.has("--dry-run") || !args.has("--close");

function shQuiet(cmd) {
  try {
    return execSync(cmd, { cwd: repoRoot, encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}

function retiredPrNumbers() {
  if (!existsSync(backlogPath)) return new Set();
  const text = readFileSync(backlogPath, "utf8");
  const nums = new Set();
  for (const m of text.matchAll(/#\s*(\d+)/g)) nums.add(Number(m[1]));
  for (const m of text.matchAll(/PR\s*#(\d+)/gi)) nums.add(Number(m[1]));
  return nums;
}

function remoteBranchExists(branch) {
  return Boolean(shQuiet(`git rev-parse --verify origin/${branch} 2>/dev/null`));
}

shQuiet("git fetch origin --prune --quiet");
const prs = JSON.parse(shQuiet('gh pr list --state open --json number,title,headRefName --limit 100') || "[]");
const retired = retiredPrNumbers();

const toClose = [];
for (const pr of prs) {
  const dead = !remoteBranchExists(pr.headRefName);
  const listed = retired.has(pr.number);
  if (dead || listed) toClose.push({ ...pr, reason: dead ? "dead branch" : "shipped/retired" });
}

if (!toClose.length) {
  console.log("No orphan PRs to close.");
  process.exit(0);
}

console.log(`Found ${toClose.length} PR(s) to close:\n`);
for (const pr of toClose) {
  console.log(`  #${pr.number} [${pr.reason}] ${pr.title}`);
}

if (dryRun) {
  console.log("\nDry run — pass --close to close these PRs.");
  process.exit(0);
}

let closed = 0;
for (const pr of toClose) {
  try {
    execSync(
      `gh pr close ${pr.number} --comment "Closed by close-orphan-prs.mjs — ${pr.reason}. Patterns shipped to main or branch retired. See docs/AUTOMATION_BACKLOG.md"`,
      { cwd: repoRoot, stdio: "inherit" }
    );
    closed++;
  } catch (e) {
    console.error(`Failed to close #${pr.number}: ${e.message}`);
  }
}
console.log(`\nClosed ${closed}/${toClose.length} PR(s).`);
