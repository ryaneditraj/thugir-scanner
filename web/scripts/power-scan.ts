#!/usr/bin/env npx tsx
/**
 * Local max-power scan for evolution automations.
 * Does NOT hit production API (no auth / rate limits).
 *
 * Usage:
 *   cd web && npx tsx scripts/power-scan.ts
 *   cd web && npx tsx scripts/power-scan.ts --benchmarks
 *   cd web && npx tsx scripts/power-scan.ts --queue
 *   cd web && npx tsx scripts/power-scan.ts --benchmarks --vulnclaw
 *   cd web && npx tsx scripts/power-scan.ts --vulnclaw --vulnclaw-deep
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runDeepScan } from "../lib/checks/runner";
import { aiDeepProbe } from "../lib/ai/deep-probe";
import { runVulnClawScan, vulnClawAvailability, mapVulnClawFindings } from "../lib/vulnclaw";
import { computeBenchmarkRecall } from "../lib/checks/benchmark-recall";

const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dir, "../..");
const LOOP = resolve(ROOT, "docs/internal/power-loop");

interface ScanEntry {
  url: string;
  auth?: string;
  id?: string;
  enabled?: boolean;
}

interface BenchmarkTarget extends ScanEntry {
  expected_categories?: string[];
}

interface BenchmarksFile {
  targets: BenchmarkTarget[];
}

interface ScanRunResult {
  run_id: string;
  url: string;
  target_id?: string;
  auth?: string;
  scan_kind: "benchmark" | "discovery";
  platform: string | null;
  finding_count: number;
  findings: Array<{
    slug: string;
    title: string;
    severity: string;
    confidence: number;
    category: string;
  }>;
  ai_findings_added: number;
  vulnclaw_findings_added?: number;
  vulnclaw_scan_mode?: string;
  pages_crawled: number;
  probes_run: number;
  status: "ok" | "error";
  error?: string;
  scanned_at: string;
}

function loadJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function recentlyScanned(url: string, runs: ScanRunResult[], hours = 48): boolean {
  const cutoff = Date.now() - hours * 60 * 60 * 1000;
  let origin: string;
  try {
    origin = new URL(url).origin;
  } catch {
    return false;
  }
  return runs.some((r) => {
    if (r.status !== "ok") return false;
    try {
      return new URL(r.url).origin === origin && new Date(r.scanned_at).getTime() > cutoff;
    } catch {
      return false;
    }
  });
}

function saveResults(run: ScanRunResult) {
  const resultsPath = resolve(LOOP, "results.json");
  const data = loadJson<{ runs: ScanRunResult[] }>(resultsPath, { runs: [] });
  data.runs.push(run);
  // Keep last 200 runs
  if (data.runs.length > 200) data.runs = data.runs.slice(-200);
  writeFileSync(resultsPath, JSON.stringify(data, null, 2));
}

async function scanOne(
  entry: ScanEntry,
  kind: "benchmark" | "discovery",
  opts?: { vulnclaw?: boolean; vulnclawMode?: "quick" | "standard" | "deep" }
): Promise<ScanRunResult> {
  const run_id = new Date().toISOString();
  const base: ScanRunResult = {
    run_id,
    url: entry.url,
    target_id: entry.id,
    auth: entry.auth,
    scan_kind: kind,
    platform: null,
    finding_count: 0,
    findings: [],
    ai_findings_added: 0,
    pages_crawled: 0,
    probes_run: 0,
    status: "ok",
    scanned_at: run_id
  };

  try {
    const deep = await runDeepScan(entry.url, { maxScripts: 24 });
    let findings = [...deep.findings];

    // AI deep probe (requires API keys in env — skips gracefully if disabled)
    try {
      const aiHits = await aiDeepProbe({
        target: deep.target,
        origin: new URL(deep.finalUrl || deep.target).origin,
        detectedPlatform: deep.detectedPlatform,
        combined: deep.combined,
        pagesCrawled: deep.pagesCrawled
      });
      if (aiHits.length) {
        const slugs = new Set(findings.map((f) => f.patternSlug));
        for (const h of aiHits) {
          if (!slugs.has(h.patternSlug)) {
            findings.push(h);
            slugs.add(h.patternSlug);
          }
        }
        base.ai_findings_added = aiHits.length;
      }
    } catch {
      /* AI layer optional */
    }

    // VulnClaw agent layer (Python) — max power when available
    if (opts?.vulnclaw) {
      const avail = vulnClawAvailability();
      if (avail.available) {
        try {
          const agent = runVulnClawScan({
            url: entry.url,
            scan_mode: opts.vulnclawMode || "quick"
          });
          if (agent.ok && agent.findings?.length) {
            const mapped = mapVulnClawFindings(agent.findings, entry.url);
            const slugs = new Set(findings.map((f) => f.patternSlug));
            let added = 0;
            for (const h of mapped) {
              if (!slugs.has(h.patternSlug)) {
                findings.push(h);
                slugs.add(h.patternSlug);
                added++;
              }
            }
            base.vulnclaw_findings_added = added;
            base.vulnclaw_scan_mode = agent.scan_mode;
          }
        } catch {
          /* agent optional */
        }
      }
    }

    base.platform = deep.detectedPlatform;
    base.pages_crawled = deep.pagesCrawled.length;
    base.probes_run = deep.probesRun;
    base.finding_count = findings.length;
    base.findings = findings.map((f) => ({
      slug: f.patternSlug,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category
    }));
    return base;
  } catch (e) {
    base.status = "error";
    base.error = e instanceof Error ? e.message : String(e);
    return base;
  }
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const useBenchmarks = args.has("--benchmarks") || args.size === 0;
  const useQueue = args.has("--queue");
  const useVulnclaw = args.has("--vulnclaw");
  const vulnclawMode = args.has("--vulnclaw-deep")
    ? "deep"
    : args.has("--vulnclaw-standard")
      ? "standard"
      : "quick";
  const limit = Number(process.env.POWER_SCAN_LIMIT || "8");

  const targets: Array<{ entry: ScanEntry; kind: "benchmark" | "discovery" }> = [];

  if (useBenchmarks) {
    const bench = loadJson<BenchmarksFile>(resolve(LOOP, "benchmarks.json"), { targets: [] });
    for (const t of bench.targets) {
      if (t.enabled === false) continue;
      targets.push({ entry: t, kind: "benchmark" });
    }
  }

  if (useQueue) {
    const resultsPath = resolve(LOOP, "results.json");
    const priorRuns = loadJson<{ runs: ScanRunResult[] }>(resultsPath, { runs: [] }).runs;
    const queue = loadJson<{ discovery_urls: ScanEntry[] }>(resolve(LOOP, "queue.json"), {
      discovery_urls: []
    });
    for (const u of queue.discovery_urls) {
      if (recentlyScanned(u.url, priorRuns)) continue;
      targets.push({ entry: u, kind: "discovery" });
    }
  }

  const slice = targets.slice(0, limit);
  if (!slice.length) {
    console.log(JSON.stringify({ ok: true, scanned: 0, note: "no targets" }));
    return;
  }

  let ok = 0;
  let findings = 0;
  const benchmarkRecall: Record<string, ReturnType<typeof computeBenchmarkRecall>> = {};

  for (const { entry, kind } of slice) {
    const result = await scanOne(entry, kind, {
      vulnclaw: useVulnclaw,
      vulnclawMode
    });
    saveResults(result);
    if (result.status === "ok") {
      ok++;
      findings += result.finding_count;
    }
    console.log(`${result.status} ${kind} ${entry.url} findings=${result.finding_count}`);

    if (kind === "benchmark" && entry.id && result.status === "ok") {
      const bench = loadJson<BenchmarksFile>(resolve(LOOP, "benchmarks.json"), { targets: [] });
      const target = bench.targets.find((t) => t.id === entry.id);
      if (target?.expected_categories?.length) {
        benchmarkRecall[entry.id] = computeBenchmarkRecall(result.findings, target.expected_categories);
      }
    }
  }

  // Update scoreboard
  const scorePath = resolve(LOOP, "scoreboard.json");
  const score = loadJson<Record<string, unknown>>(scorePath, {});
  score.updated_at = new Date().toISOString();
  score.last_run = new Date().toISOString();
  score.total_sites_scanned = Number(score.total_sites_scanned || 0) + ok;
  score.total_findings = Number(score.total_findings || 0) + findings;
  if (Object.keys(benchmarkRecall).length) {
    score.benchmark_recall = {
      ...(typeof score.benchmark_recall === "object" && score.benchmark_recall !== null
        ? (score.benchmark_recall as Record<string, unknown>)
        : {}),
      ...benchmarkRecall
    };
  }
  const shipped = loadJson<{ shipped: unknown[] }>(resolve(LOOP, "improvements.json"), { shipped: [] });
  score.improvements_shipped = shipped.shipped?.length ?? Number(score.improvements_shipped || 0);
  writeFileSync(scorePath, JSON.stringify(score, null, 2));

  console.log(JSON.stringify({ ok: true, scanned: ok, findings, limit }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
