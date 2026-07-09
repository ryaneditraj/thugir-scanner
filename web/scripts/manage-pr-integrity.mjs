#!/usr/bin/env node
/**
 * Audit and deconflict open detection PRs.
 *
 * Usage:
 *   node scripts/manage-pr-integrity.mjs --audit          # report only (exit 1 on issues)
 *   node scripts/manage-pr-integrity.mjs --fix-backlog    # reset AUTOMATION_BACKLOG.md on open PR branches
 *   node scripts/manage-pr-integrity.mjs --prune-branches  # delete orphan auto/detection/* branches
 *   node scripts/manage-pr-integrity.mjs --retire-superseded  # integrity PRs + backlog Retired only
 *   node scripts/manage-pr-integrity.mjs --retire-superseded --retire-detection-duplicates  # also slug dupes
 *   node scripts/manage-pr-integrity.mjs --retire-superseded --dry-run  # preview without deleting
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
const retireSuperseded = args.has("--retire-superseded");
const retireDetectionDuplicates = args.has("--retire-detection-duplicates");
const dryRun = args.has("--dry-run");

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

function retiredPrNumbers() {
  if (!existsSync(backlogPath)) return new Set();
  const text = readFileSync(backlogPath, "utf8");
  const retiredSection = text.split("## Retired")[1]?.split("##")[0] || "";
  const sectionNums = new Set();
  for (const m of retiredSection.matchAll(/^-\s+\*\*([^*]+)\*\*/gm)) {
    for (const n of m[1].matchAll(/#(\d+)/g)) sectionNums.add(Number(n[1]));
  }
  return sectionNums;
}

function detectionSlugForPr(pr, mainSlugs) {
  const branchSlugs = getBranchSlugs(pr.headRefName);
  return [...branchSlugs].filter((s) => !mainSlugs.has(s));
}

function getPatternFiles(ref) {
  const patternsDir = "web/lib/patterns";
  return shQuiet(`git ls-tree -r --name-only ${ref} -- ${patternsDir}`)
    .split("\n")
    .filter((f) => f.endsWith(".ts") && !f.endsWith("types.ts") && !f.endsWith("index.ts"));
}

/** Fingerprints per slug so we can detect modifications to existing slugs, not just new ones. */
function extractSlugBlock(text, slug) {
  const marker = `slug: "${slug}"`;
  const idx = text.indexOf(marker);
  if (idx < 0) return "";
  const rest = text.slice(idx);
  const end = rest.match(/\n  \},?/);
  const raw = end ? rest.slice(0, end.index + end[0].length) : rest.slice(0, 400);
  return raw
    .replace(/,\s*$/, "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//"))
    .join("\n");
}

function slugFingerprints(ref) {
  const map = new Map();
  for (const file of getPatternFiles(ref)) {
    const text = shQuiet(`git show ${ref}:${file}`);
    if (!text) continue;
    for (const block of text.split(/slug:\s*"/).slice(1)) {
      const slug = block.match(/^([^"]+)"/)?.[1];
      if (!slug) continue;
      const fp = extractSlugBlock(text, slug);
      if (fp) map.set(slug, (map.get(slug) || "") + `\0${file}:${fp}`);
    }
  }
  return map;
}

function changedSlugsForPr(pr) {
  if (!remoteBranchExists(pr.headRefName)) return [];
  const mainFp = slugFingerprints("origin/main");
  const branchFp = slugFingerprints(`origin/${pr.headRefName}`);
  return [...branchFp.entries()]
    .filter(([slug, fp]) => !mainFp.has(slug) || mainFp.get(slug) !== fp)
    .map(([slug]) => slug);
}

function auditPrs() {
  shQuiet("git fetch origin --prune --quiet");
  const issues = [];
  const prs = getOpenPrs();
  const mainSlugs = getMainSlugs();
  const retired = retiredPrNumbers();

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
      const isIntegrity =
        /pull-request-integrity/i.test(pr.headRefName) || /PR integrity/i.test(pr.title);
      const isRetired = isIntegrity || retired.has(pr.number);
      const msg = `PR #${pr.number} head branch missing on origin: ${pr.headRefName}`;
      console.log(`  ${isRetired ? "INFO" : "ERROR"}: ${msg}${isRetired ? " (retired shell)" : ""}`);
      issues.push({
        kind: isRetired ? "retired-pr-shell" : "missing-branch",
        pr: pr.number,
        branch: pr.headRefName,
      });
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
    const changedSlugs = remoteBranchExists(pr.headRefName) ? changedSlugsForPr(pr) : [];
    const modifiedSlugs = changedSlugs.filter((s) => mainSlugs.has(s));
    console.log(`PR #${pr.number}: ${pr.title}`);
    console.log(`  branch: ${pr.headRefName}  draft: ${pr.isDraft}`);
    console.log(`  new slugs (${newSlugs.length}): ${newSlugs.join(", ") || "(none)"}`);
    if (modifiedSlugs.length) {
      console.log(`  modified slugs (${modifiedSlugs.length}): ${modifiedSlugs.join(", ")}`);
    }

    for (const slug of changedSlugs) {
      if (!slugOwners.has(slug)) slugOwners.set(slug, []);
      slugOwners.get(slug).push(pr.number);
    }
  }

  const integrityPrs = prs.filter((p) =>
    /pull-request-integrity/i.test(p.headRefName) || /PR integrity/i.test(p.title)
  );
  const liveIntegrityPrs = integrityPrs.filter((p) => remoteBranchExists(p.headRefName));
  if (liveIntegrityPrs.length > 1) {
    console.log("\n--- Multiple open integrity PRs (close superseded duplicates) ---");
    const nums = liveIntegrityPrs.map((p) => `#${p.number}`).join(", ");
    console.log(`  ERROR: ${liveIntegrityPrs.length} live integrity PRs: ${nums}`);
    for (const p of liveIntegrityPrs) {
      console.log(`    #${p.number} ${p.headRefName}`);
      issues.push({ kind: "duplicate-integrity-pr", pr: p.number, branch: p.headRefName, dead: false });
    }
  }
  const deadIntegrity = integrityPrs.filter((p) => !remoteBranchExists(p.headRefName));
  if (deadIntegrity.length) {
    console.log("\n--- Retired integrity PR shells (branch deleted, close on GitHub when possible) ---");
    for (const p of deadIntegrity) {
      console.log(`  INFO: #${p.number} ${p.headRefName} (DEAD BRANCH)`);
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

function supersededPrNumbers(prs) {
  const retired = retiredPrNumbers();
  const toSkip = new Set(retired);

  const integrityPrs = prs.filter(
    (p) => /pull-request-integrity/i.test(p.headRefName) || /PR integrity/i.test(p.title)
  );
  const liveIntegrity = integrityPrs.filter((p) => remoteBranchExists(p.headRefName));
  if (liveIntegrity.length > 1) {
    liveIntegrity.sort((a, b) => b.number - a.number);
    for (const p of liveIntegrity.slice(1)) toSkip.add(p.number);
  }

  const slugOwners = new Map();
  for (const pr of prs) {
    if (!remoteBranchExists(pr.headRefName)) continue;
    for (const slug of changedSlugsForPr(pr)) {
      if (!slugOwners.has(slug)) slugOwners.set(slug, []);
      slugOwners.get(slug).push(pr.number);
    }
  }
  for (const owners of slugOwners.values()) {
    if (owners.length <= 1) continue;
    owners.sort((a, b) => a - b);
    for (const prNum of owners.slice(1)) toSkip.add(prNum);
  }

  return toSkip;
}

function fixBacklogOnBranches() {
  if (!existsSync(backlogPath)) {
    console.error("Missing docs/AUTOMATION_BACKLOG.md — run from repo with canonical backlog.");
    process.exit(1);
  }
  const canonical = readFileSync(backlogPath, "utf8");
  const prs = getOpenPrs();
  const skipPrs = supersededPrNumbers(prs);

  const startBranch = shQuiet("git branch --show-current") || "main";
  shQuiet("git stash push -u -m pr-integrity-fix-backlog 2>/dev/null || true");

  for (const pr of prs) {
    const branch = pr.headRefName;
    if (skipPrs.has(pr.number)) {
      console.log(`\nSkipping PR #${pr.number} (retired/superseded)`);
      continue;
    }
    console.log(`\nFixing backlog on ${branch} (PR #${pr.number})...`);
    shQuiet(`git fetch origin ${branch} --quiet`);
    if (!remoteBranchExists(branch)) {
      console.log(`  skipping — origin/${branch} not found`);
      continue;
    }
    shQuiet("git reset --hard HEAD 2>/dev/null || true");
    shQuiet("git clean -fd 2>/dev/null || true");
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
  shQuiet("git stash pop 2>/dev/null || true");
}

function pruneOrphanBranches() {
  shQuiet("git fetch origin --prune --quiet");
  const prs = getOpenPrs();
  const prHeads = new Set(prs.map((p) => p.headRefName));
  const orphans = getRemoteBranches("auto/detection/").filter((b) => !prHeads.has(b));

  if (!orphans.length) {
    console.log("No orphan auto/detection branches to prune.");
    return;
  }

  for (const b of orphans) {
    const orphanSlugs = getBranchSlugs(b);
    const cursorMatch = prs.find((p) => {
      if (!remoteBranchExists(p.headRefName) || !p.headRefName.startsWith("cursor/")) return false;
      const prSlugs = detectionSlugForPr(p, getMainSlugs());
      if (prSlugs.some((s) => orphanSlugs.has(s))) return true;
      if (!remoteBranchExists(b)) return false;
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

/** Delete remote branches for superseded integrity PRs and backlog Retired entries only (safe default). */
function retireSupersededBranches() {
  shQuiet("git fetch origin --prune --quiet");
  const prs = getOpenPrs();
  const toRetire = new Set();
  const retired = retiredPrNumbers();

  for (const pr of prs) {
    if (retired.has(pr.number)) {
      console.log(`Mark PR #${pr.number} for retirement (listed in backlog Retired section)`);
      toRetire.add(pr.number);
    }
  }

  if (retireDetectionDuplicates) {
    const slugOwners = new Map();
    for (const pr of prs) {
      if (!remoteBranchExists(pr.headRefName)) continue;
      for (const slug of changedSlugsForPr(pr)) {
        if (!slugOwners.has(slug)) slugOwners.set(slug, []);
        slugOwners.get(slug).push(pr.number);
      }
    }

    for (const [slug, owners] of slugOwners) {
      if (owners.length <= 1) continue;
      owners.sort((a, b) => a - b);
      const keeper = owners[0];
      for (const prNum of owners.slice(1)) {
        console.log(`Mark PR #${prNum} for retirement (duplicate slug "${slug}", keeper #${keeper})`);
        toRetire.add(prNum);
      }
    }
  } else {
    console.log("Skipping detection slug duplicates (pass --retire-detection-duplicates to enable).");
  }

  const integrityPrs = prs.filter(
    (p) => /pull-request-integrity/i.test(p.headRefName) || /PR integrity/i.test(p.title)
  );
  if (integrityPrs.length > 1) {
    integrityPrs.sort((a, b) => b.number - a.number);
    const keeper = integrityPrs[0];
    for (const p of integrityPrs.slice(1)) {
      console.log(`Mark PR #${p.number} for retirement (superseded integrity, keeper #${keeper.number})`);
      toRetire.add(p.number);
    }
  }

  if (!toRetire.size) {
    console.log("No superseded PR branches to retire.");
    return;
  }

  for (const prNum of toRetire) {
    const pr = prs.find((p) => p.number === prNum);
    if (!pr) continue;
    if (!remoteBranchExists(pr.headRefName)) {
      console.log(`PR #${prNum} branch already gone: ${pr.headRefName}`);
      continue;
    }
    if (dryRun) {
      console.log(`[dry-run] Would delete branch ${pr.headRefName} (PR #${prNum})`);
      continue;
    }
    console.log(`Deleting branch ${pr.headRefName} (PR #${prNum})`);
    shQuiet(`git push origin --delete ${pr.headRefName}`);
  }
}

// --- main ---
if (fixBacklog) fixBacklogOnBranches();
if (pruneBranches) pruneOrphanBranches();
if (retireSuperseded) retireSupersededBranches();

if (audit) {
  const issues = auditPrs();
  const serious = issues.filter(
    (i) =>
      i.kind === "orphan-branch" ||
      i.kind === "duplicate-title" ||
      i.kind === "duplicate-slug" ||
      i.kind === "duplicate-pr" ||
      i.kind === "missing-branch" ||
      i.kind === "duplicate-integrity-pr"
  );
  if (serious.length > 0 && !fixBacklog && !pruneBranches && !retireSuperseded) {
    process.exit(1);
  }
}
