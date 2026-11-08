/**
 * Run the free-tier engine against one URL. No Supabase account required.
 * Usage: npm run scan -- https://example.com
 */
import { runFreeScan } from "../lib/checks/runner";

const target = process.argv[2];
if (!target) {
  console.error("Usage: npm run scan -- https://example.com");
  process.exit(2);
}

const started = Date.now();
try {
  const result = await runFreeScan(target);
  const lines = result.findings.map((finding) => {
    const evidence = finding.evidence ? JSON.stringify(finding.evidence).slice(0, 240) : "";
    return `[${finding.severity}] ${finding.title}\n    ${finding.impactOneline}\n    ${evidence}`;
  });
  console.log(`target: ${result.finalUrl || result.target}`);
  console.log(`platform: ${result.detectedPlatform ?? "unknown"}`);
  console.log(`findings: ${result.findings.length}`);
  console.log(`locked deep-tier checks (titles only): ${result.lockedTeasers.length}`);
  console.log(`elapsed_ms: ${Date.now() - started}`);
  console.log(lines.join("\n") || "(no free-tier finding fired)");
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}
