#!/usr/bin/env node
/**
 * Audit and deconflict open detection PRs.
 *
 * Usage:
 *   node scripts/manage-pr-integrity.mjs --audit          # report only (exit 1 on issues)
 *   node scripts/manage-pr-integrity.mjs --fix-backlog    # reset AUTOMATION_BACKLOG.md on open PR branches
 *   node scripts/manage-pr-integrity.mjs --prune-branches  # delete orphan auto/detection/* branches
 */
import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "../..");
const backlogPath = join(repoRoot, "docs/AUTOMATION_BACKLOG.md");
const catalogPath = join(repoRoot, "docs/internal/pattern-catalog.json");

const args = new Set(process.argv.slice(2));
const audit = args.has("--audit") || args.size === 0;
const fixBacklog = args.has("--fix-backlog");
const pruneBranches = args.has("--prune-branches");

function sh(cmd, opts = {}) {
  return execSync(cmd, { cwd: repoRoot, encoding: "utf8", stdio: opts.silent ? "pipe" : "inherit", ...opts });
}

function shQuiet(cmd) {
  try {
    return sh(cmd, { silent: true }).trim();
  } catch {
    return "";
  }
}

function getOpenPrs() {
  const raw = shQuiet(
    'gh pr list --state open --json number,title,headRefName,baseRefName,isDraft --limit 100'
  );
  if (!raw) return [];
  return JSON.parse(raw);
}

function getSlugsFromRef(ref) {
  const patternsDir = "web/lib/patterns";
  const files = shQuiet(`git ls-tree -r --name-only ${ref} -- ${patternsDir}`)
    .split("\n")
    .filter((f) => f.endsWith(".ts") && !f.endsWith("types.ts") && !f.endsWith("index.ts"));

  const slugs = new Set();
  for (const file of files) {
    const text = shQuiet(`git show ${ref}:${file}`);
    if (!text) continue;
    for (const block of text.split(/slug:\s*"/).slice(1)) {
      const slug = block.match(/^([^"]+)"/)?.[1];
      if (slug) slugs.add(slug);
    }
  }
  return slugs;
}

function getMainSlugs() {
  shQuiet("git fetch origin main --quiet");
  return getSlugsFromRef("origin/main");
}

function getBranchSlugs(branch) {
  return getSlugsFromRef(`origin/${branch}`);
}

function getRemoteBranches(prefix) {
  const lines = shQuiet("git branch -r --list").split("\n").filter(Boolean);
  return lines
    .map((l) => l.trim().replace(/^origin\//, ""))
    .filter((b) => b.startsWith(prefix));
}

function remoteBranchExists(branch) {
  return Boolean(shQuiet(`git rev-parse --verify origin/${branch} 2>/dev/null`));
}

function branchTip(branch) {
  return shQuiet(`git rev-parse origin/${branch} 2>/dev/null`);
}

function detectionSlugForPr(pr, mainSlugs) {
  const branchSlugs = getBranchSlugs(pr.headRefName);
  return [...branchSlugs].filter((s) => !mainSlugs.has(s));
}

function auditPrs() {
  const issues = [];
  const prs = getOpenPrs();
  const mainSlugs = getMainSlugs();

  if (prs.length === 0) {
    console.log("No open PRs.");
    return issues;
  }

  console.log(`\n=== PR integrity audit (${prs.length} open) ===\n`);

  const slugOwners = new Map();
  const fileOwners = new Map();
  const titles = new Map();
  const tipOwners = new Map();

  for (const pr of prs) {
    if (!remoteBranchExists(pr.headRefName)) {
      const msg = `PR #${pr.number} head branch missing on origin: ${pr.headRefName}`;
      console.log(`  ERROR: ${msg}`);
      issues.push({ kind: "missing-branch", pr: pr.number, branch: pr.headRefName });
    } else {
      const tip = branchTip(pr.headRefName);
      if (tipOwners.has(tip)) {
        const other = tipOwners.get(tip);
        const msg = `PR #${pr.number} duplicates PR #${other} (same commit ${tip.slice(0, 7)})`;
        console.log(`  ERROR: ${msg}`);
        issues.push({ kind: "duplicate-pr", pr: pr.number, other, sha: tip });
      } else {
        tipOwners.set(tip, pr.number);
      }
    }

    if (titles.has(pr.title)) {
      issues.push({ kind: "duplicate-title", pr: pr.number, detail: `Duplicate title with PR #${titles.get(pr.title)}` });
    } else {
      titles.set(pr.title, pr.number);
    }

    const files = shQuiet(`gh pr view ${pr.number} --json files -q '.files[].path'`).split("\n").filter(Boolean);
    for (const f of files) {
      if (!fileOwners.has(f)) fileOwners.set(f, []);
      fileOwners.get(f).push(pr.number);
    }

    const newSlugs = detectionSlugForPr(pr, mainSlugs);
    console.log(`PR #${pr.number}: ${pr.title}`);
    console.log(`  branch: ${pr.headRefName}  draft: ${pr.isDraft}`);
    console.log(`  new slugs (${newSlugs.length}): ${newSlugs.join(", ") || "(none)"}`);

    for (const slug of newSlugs) {
      if (!slugOwners.has(slug)) slugOwners.set(slug, []);
      slugOwners.get(slug).push(pr.number);
    }
  }

  console.log("\n--- Cross-PR slug collisions (true duplicate detections) ---");
  for (const [slug, owners] of [...slugOwners.entries()].sort()) {
    if (owners.length > 1) {
      const msg = `Slug "${slug}" in PRs: ${owners.join(", ")}`;
      console.log(`  WARN: ${msg}`);
      issues.push({ kind: "duplicate-slug", slug, prs: owners });
    }
  }

  console.log("\n--- Hot files (merge conflict risk — expected until PRs land) ---");
  const hotFiles = ["docs/AUTOMATION_BACKLOG.md", "docs/internal/pattern-catalog.json", "supabase/seed/patterns.sql"];
  for (const f of hotFiles) {
    const owners = fileOwners.get(f) || [];
    if (owners.length > 1) {
      const msg = `${f} touched by PRs: ${owners.join(", ")}`;
      console.log(`  WARN: ${msg}`);
      issues.push({ kind: "hot-file", file: f, prs: owners });
    }
  }

  // Orphan auto/detection branches (no open PR head)
  const prHeads = new Set(prs.map((p) => p.headRefName));
  const autoBranches = getRemoteBranches("auto/detection/");
  const orphans = autoBranches.filter((b) => !prHeads.has(b));
  if (orphans.length) {
    console.log("\n--- Orphan auto/detection branches (duplicate of cursor PR branches) ---");
    for (const b of orphans) {
      console.log(`  ORPHAN: ${b}`);
      issues.push({ kind: "orphan-branch", branch: b });
    }
  }

  console.log(`\n=== ${issues.length} issue(s) found ===\n`);
  return issues;
}

function fixBacklogOnBranches() {
  if (!existsSync(backlogPath)) {
    console.error("Missing docs/AUTOMATION_BACKLOG.md — run from repo with canonical backlog.");
    process.exit(1);
  }
  const canonical = readFileSync(backlogPath, "utf8");
  const prs = getOpenPrs();

  const startBranch = shQuiet("git branch --show-current") || "main";
  shQuiet("git stash push -m pr-integrity-fix-backlog -- docs/AUTOMATION_BACKLOG.md 2>/dev/null || true");

  for (const pr of prs) {
    const branch = pr.headRefName;
    console.log(`\nFixing backlog on ${branch} (PR #${pr.number})...`);
    shQuiet(`git fetch origin ${branch} --quiet`);
    if (!remoteBranchExists(branch)) {
      console.log(`  skipping — origin/${branch} not found`);
      continue;
    }
    sh(`git checkout -B pr-fix-${pr.number} origin/${branch}`);
    sh(`git checkout origin/main -- docs/AUTOMATION_BACKLOG.md 2>/dev/null || true`, { silent: true });
    // Write canonical backlog (main may not have it yet on first run)
    execSync(`cat > docs/AUTOMATION_BACKLOG.md`, { cwd: repoRoot, input: canonical });
    const hasDiff = shQuiet("git diff --name-only docs/AUTOMATION_BACKLOG.md");
    if (!hasDiff) {
      console.log("  backlog already canonical, skipping commit");
      shQuiet(`git checkout ${branch} 2>/dev/null || git checkout main`);
      shQuiet(`git branch -D pr-fix-${pr.number}`);
      continue;
    }
    sh('git add docs/AUTOMATION_BACKLOG.md');
    sh(`git commit -m "chore: canonical AUTOMATION_BACKLOG.md (PR integrity pass)"`);
    sh(`git push origin HEAD:${branch}`);
    shQuiet(`git branch -D pr-fix-${pr.number}`);
  }
  shQuiet(`git checkout ${startBranch} 2>/dev/null || git checkout main`);
}

function pruneOrphanBranches() {
  const prs = getOpenPrs();
  const prHeads = new Set(prs.map((p) => p.headRefName));
  const orphans = getRemoteBranches("auto/detection/").filter((b) => !prHeads.has(b));

  if (!orphans.length) {
    console.log("No orphan auto/detection branches to prune.");
    return;
  }

  for (const b of orphans) {
    // Only delete if an equivalent cursor branch exists with same tip or superset
    const autoTip = shQuiet(`git rev-parse origin/${b}`);
  const cursorMatch = prs.find((p) => {
      const cursorTip = shQuiet(`git rev-parse origin/${p.headRefName}`);
      const diff = shQuiet(`git diff --stat origin/${b} origin/${p.headRefName}`);
      return diff === "" || diff.includes("1 file changed");
    });

    if (cursorMatch) {
      console.log(`Deleting orphan ${b} (covered by PR #${cursorMatch.number})`);
      shQuiet(`git push origin --delete ${b}`);
    } else {
      console.log(`Keeping ${b} — no matching cursor PR branch`);
    }
  }
}

// --- main ---
if (fixBacklog) fixBacklogOnBranches();
if (pruneBranches) pruneOrphanBranches();

if (audit) {
  const issues = auditPrs();
  const serious = issues.filter(
    (i) =>
      i.kind === "orphan-branch" ||
      i.kind === "duplicate-title" ||
      i.kind === "duplicate-slug" ||
      i.kind === "duplicate-pr" ||
      i.kind === "missing-branch"
  );
  if (serious.length > 0 && !fixBacklog && !pruneBranches) {
    process.exit(1);
  }
}
