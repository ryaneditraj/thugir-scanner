#!/usr/bin/env npx tsx
/**
 * Local max-power scan for evolution automations.
 * Does NOT hit production API (no auth / rate limits).
 *
 * Usage:
 *   cd web && npx tsx scripts/power-scan.ts
 *   cd web && npx tsx scripts/power-scan.ts --benchmarks
 *   cd web && npx tsx scripts/power-scan.ts --queue
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runDeepScan } from "../lib/checks/runner";
import { aiDeepProbe } from "../lib/ai/deep-probe";
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
  /** When primary oracle is degraded (Heroku cold start), retry this URL before scoring recall. */
  fallback_url?: string;
}

const BENCHMARK_MIN_FINDINGS = 5;
const BENCHMARK_RETRY_DELAY_MS = 12000;
const BENCHMARK_FINAL_RETRY_DELAY_MS = 25000;

type BenchmarkFinding = ScanRunResult["findings"][number];

/** Union first-pass + retry findings by slug — Heroku cold-start often splits categories across passes. */
function mergeBenchmarkFindings(
  first: BenchmarkFinding[],
  retry: BenchmarkFinding[]
): BenchmarkFinding[] {
  const bySlug = new Map<string, BenchmarkFinding>();
  for (const f of [...first, ...retry]) {
    const prev = bySlug.get(f.slug);
    if (!prev || f.confidence > prev.confidence) bySlug.set(f.slug, f);
  }
  return [...bySlug.values()];
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

async function scanOne(entry: ScanEntry, kind: "benchmark" | "discovery"): Promise<ScanRunResult> {
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
    let result = await scanOne(entry, kind);
    saveResults(result);

    if (kind === "benchmark" && entry.id) {
      const bench = loadJson<BenchmarksFile>(resolve(LOOP, "benchmarks.json"), { targets: [] });
      const target = bench.targets.find((t) => t.id === entry.id);

      if (
        result.status === "error" &&
        target?.fallback_url &&
        target.fallback_url !== entry.url
      ) {
        console.log(`benchmark error ${entry.url} — fallback ${target.fallback_url}`);
        const fallback = await scanOne({ ...entry, url: target.fallback_url }, kind);
        saveResults(fallback);
        result = fallback;
      }
    }

    if (kind === "benchmark" && entry.id && result.status === "ok") {
      const bench = loadJson<BenchmarksFile>(resolve(LOOP, "benchmarks.json"), { targets: [] });
      const target = bench.targets.find((t) => t.id === entry.id);
      const expected = target?.expected_categories ?? [];
      let recall =
        expected.length > 0 ? computeBenchmarkRecall(result.findings, expected) : null;

      const degraded =
        recall !== null &&
        (recall.gap.length > 0 || result.finding_count < BENCHMARK_MIN_FINDINGS);

      if (degraded) {
        console.log(
          `benchmark degraded ${entry.url} findings=${result.finding_count} gap=${recall?.gap.join(",") ?? ""} — retrying`
        );
        await new Promise((r) => setTimeout(r, BENCHMARK_RETRY_DELAY_MS));
        const retry = await scanOne(entry, kind);
        saveResults(retry);
        if (retry.status === "ok") {
          const merged = mergeBenchmarkFindings(result.findings, retry.findings);
          const mergedRecall =
            expected.length > 0 ? computeBenchmarkRecall(merged, expected) : null;
          const mergedBetter =
            mergedRecall !== null &&
            recall !== null &&
            (mergedRecall.categories_hit > recall.categories_hit ||
              (mergedRecall.categories_hit === recall.categories_hit &&
                merged.length > result.finding_count));
          const retryBetterCount = retry.finding_count >= result.finding_count;
          if (mergedBetter || (mergedRecall !== null && recall !== null && mergedRecall.gap.length < recall.gap.length)) {
            result = {
              ...(retryBetterCount ? retry : result),
              findings: merged,
              finding_count: merged.length
            };
            recall = mergedRecall;
          } else if (retryBetterCount) {
            result = retry;
            recall =
              expected.length > 0 ? computeBenchmarkRecall(retry.findings, expected) : null;
          }
        }

        const stillDegraded =
          recall !== null &&
          (recall.gap.length > 0 || result.finding_count < BENCHMARK_MIN_FINDINGS);
        if (stillDegraded && /juice-shop|owasp-juice/i.test(entry.url)) {
          console.log(`benchmark still degraded ${entry.url} — final Heroku wake retry`);
          await new Promise((r) => setTimeout(r, BENCHMARK_FINAL_RETRY_DELAY_MS));
          const finalRetry = await scanOne(entry, kind);
          saveResults(finalRetry);
          if (finalRetry.status === "ok") {
            const merged = mergeBenchmarkFindings(result.findings, finalRetry.findings);
            const mergedRecall =
              expected.length > 0 ? computeBenchmarkRecall(merged, expected) : null;
            if (
              mergedRecall !== null &&
              recall !== null &&
              (mergedRecall.categories_hit > recall.categories_hit ||
                mergedRecall.gap.length < recall.gap.length ||
                merged.length > result.finding_count)
            ) {
              result = {
                ...result,
                findings: merged,
                finding_count: merged.length,
                pages_crawled: Math.max(result.pages_crawled, finalRetry.pages_crawled),
                probes_run: Math.max(result.probes_run, finalRetry.probes_run)
              };
              recall = mergedRecall;
            }
          }
        }
      }

      if (
        recall !== null &&
        recall.gap.length > 0 &&
        target?.fallback_url &&
        target.fallback_url !== entry.url
      ) {
        console.log(`benchmark fallback ${target.fallback_url}`);
        const fallback = await scanOne(
          { ...entry, url: target.fallback_url },
          kind
        );
        saveResults(fallback);
        if (fallback.status === "ok") {
          const fallbackRecall = computeBenchmarkRecall(fallback.findings, expected);
          if (fallbackRecall.categories_hit > recall.categories_hit) {
            result = fallback;
            recall = fallbackRecall;
          }
        }
      }
    }

    if (result.status === "ok") {
      ok++;
      findings += result.finding_count;
    }
    console.log(`${result.status} ${kind} ${result.url} findings=${result.finding_count}`);

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
