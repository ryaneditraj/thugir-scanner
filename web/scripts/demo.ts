/* Offline demo of the Thugir free-tier engine.
 *
 * Runs the real secret detector and the security-header rule against an in-memory fixture.
 * No network. The fixture strings are invented.
 * Run: npm run demo
 */
import { runSyntheticFixtureScan } from "../lib/demo/fixture";
import { serializeFindings } from "../lib/findings/gate";
import type { PatternFinding } from "../lib/patterns/types";

function hr(t: string) {
  console.log(`\n\x1b[1m${t}\x1b[0m`);
}

async function main() {
const scan = await runSyntheticFixtureScan();
console.log("\x1b[1m=== Thugir free-tier scan demo (offline, synthetic fixture) ===\x1b[0m");
console.log(scan.label);
console.log(`Loaded ${scan.librarySize} enabled patterns. ${scan.freeChecks} are free-tier.`);

hr("1) AI-builder detection");
console.log(`   detected platform: ${scan.detectedPlatform}`);
console.log(`   signals: ${scan.signals.join(", ")}`);

hr("2) Detector output on the invented page");
for (const f of scan.findings) {
  console.log(`   [${f.severity.toUpperCase()}] ${f.title}`);
  console.log(`        impact: ${f.impactOneline}`);
  console.log(`        evidence: ${JSON.stringify(f.evidence)}`);
}

hr("3) Server-side blur gate");
console.log(`   ${scan.findings.length} unlocked findings + ${scan.locked.checkCount} locked checks (count only)`);

hr("4) A deep-tier copy of the first finding, shown to a free caller");
const first = scan.rawFindings[0];
if (first) {
  const locked = serializeFindings([{ ...first, tierRequired: "deep" } as PatternFinding], "free")[0] as {
    evidence?: unknown;
  };
  console.log(`   includes evidence? ${"evidence" in locked && locked.evidence != null}`);
  console.log("   gated fields are absent from the payload, not hidden in the DOM.");
}

console.log("\n\x1b[1m=== demo complete ===\x1b[0m");
}

main();
