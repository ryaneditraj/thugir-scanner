import assert from "node:assert/strict";
import { runSyntheticFixtureScan } from "../lib/demo/fixture";
import { reportMarkdown } from "../lib/share/report-markdown";

async function main() {
const scan = await runSyntheticFixtureScan();

assert.equal(scan.synthetic, true);
assert.match(scan.target, /synthetic\.invalid/);
assert.ok(scan.freeChecks > 0);
assert.ok(scan.librarySize > scan.freeChecks);
assert.ok(scan.findings.length > 0, "fixture should trip at least one free-tier detector");
assert.ok(scan.signals.includes("lovable"));
assert.ok(scan.signals.includes("supabase"));

for (const finding of scan.findings) {
  assert.equal(finding.unlocked, true);
  assert.ok(finding.evidence, `${finding.title} is missing evidence`);
}

const headers = scan.findings.find((f) => f.title.toLowerCase().includes("header"));
assert.ok(headers, "missing-header rule should fire on the fixture response");
const missing = (headers!.evidence as { missing?: string[] }).missing ?? [];
assert.ok(missing.includes("Content-Security-Policy"));

const secrets = scan.findings.filter((f) => f.evidence && "sampleRedacted" in f.evidence);
assert.ok(secrets.length > 0, "secret detector should redact a sample from the invented bundle");

const markdown = reportMarkdown({
  synthetic: true,
  target: scan.target,
  detectedPlatform: scan.detectedPlatform,
  findings: scan.findings
});
assert.match(markdown, /^SYNTHETIC FIXTURE/);
assert.doesNotMatch(markdown, /1,402|customers|benchmark|years of research/i);

console.log(`fixture scan: ${scan.findings.length} findings, ${scan.freeChecks} free checks, ${scan.librarySize} library patterns`);
console.log(markdown);
}

main();
