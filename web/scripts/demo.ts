/* Offline demo of the Thugir free-tier engine.
 *
 * Exercises the REAL library code (pattern library + secret detector + AI-builder detection +
 * server-side blur gate) against a synthetic "vibe-coded" app bundle - no network, no Supabase.
 * Run: npx tsx scripts/demo.ts
 */
import {
  STATIC_PATTERNS,
  patternsForTier,
  lockedTeasersForPlatform,
  type Pattern,
  type PatternFinding
} from "../lib/patterns";
import { serializeFindings } from "../lib/findings/gate";
import { detectPlatform } from "../lib/detect";

// --- Build a synthetic client bundle that a Lovable + Supabase app might ship ---
function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
// A realistic Supabase service_role JWT (decodes to role: service_role).
const SERVICE_ROLE_JWT = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({
  iss: "supabase",
  role: "service_role"
})}.dummrepresentativesignaturedummyrepresentativesig123456`;

const FAKE_BUNDLE = `
<!doctype html><html><head>
  <script src="/assets/index-ab12.js"></script>
  <meta name="generator" content="gptengineer / lovable.dev">
</head><body>
<script>
  // shipped by the AI builder into the browser:
  const SUPABASE_URL = "https://abcdef0123456789klmn.supabase.co";
  const SUPABASE_SERVICE_ROLE = "${SERVICE_ROLE_JWT}";
  const STRIPE = "sk_live_51QexampleKEY0123456789abcDEF";
  const firebaseConfig = { apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuvx" };
  const OPENAI_KEY = "sk-proj-abcdEFGH1234567890ijklmnopqrstuv";
  fetch("/api/webhooks/stripe", { method: "POST" }); // no signature check anywhere
</script>
</body></html>`;

const fakeHome: any = {
  url: "https://demo-app.example",
  finalUrl: "https://demo-app.example",
  status: 200,
  ok: true,
  headers: { "content-type": "text/html" }, // note: no CSP / HSTS / X-Frame-Options
  body: FAKE_BUNDLE,
  truncated: false
};

// --- Mirror of runner.scanSecret (kept tiny) so the demo needs no network ---
function scanSecret(pattern: Pattern, combined: string): PatternFinding | null {
  if (pattern.detectorKind !== "secret_regex") return null;
  const cfg = pattern.detectorConfig as { regex: string; validate?: string; secretName: string };
  const matches = combined.match(new RegExp(cfg.regex, "gi"));
  if (!matches) return null;
  if (cfg.validate) {
    const ok = matches.some((m) => {
      try {
        return atob(m.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")).includes(cfg.validate!);
      } catch {
        return m.includes(cfg.validate!);
      }
    });
    if (!ok) return null;
  }
  const s = matches[0];
  return {
    patternSlug: pattern.slug,
    category: pattern.category,
    title: pattern.title,
    severity: pattern.severityDefault,
    tierRequired: pattern.tierRequired,
    impactOneline: pattern.impactOneline,
    evidence: { secretName: cfg.secretName, sampleRedacted: `${s.slice(0, 6)}...${s.slice(-4)}` },
    remediation: pattern.remediation,
    fixPrompt: pattern.fixPrompt,
    confidence: 0.9
  };
}

function hr(t: string) {
  console.log(`\n\x1b[1m${t}\x1b[0m`);
}

// --- Run ---
console.log("\x1b[1m=== Thugir free-tier scan demo (offline, synthetic target) ===\x1b[0m");
console.log(`Loaded ${STATIC_PATTERNS.length} patterns from the library.`);

const detection = detectPlatform(fakeHome, FAKE_BUNDLE);
hr("1) AI-builder detection");
console.log(`   detected platform: ${detection.platform}`);
console.log(`   signals: ${detection.signals.join(", ")}`);

hr("2) Free-tier secret findings (single-pass over the bundle)");
const findings: PatternFinding[] = [];
for (const p of patternsForTier("free")) {
  const f = scanSecret(p, FAKE_BUNDLE);
  if (f) findings.push(f);
}
for (const f of findings) {
  console.log(`   [${f.severity.toUpperCase()}] ${f.title}`);
  console.log(`        impact: ${f.impactOneline}`);
  console.log(`        evidence: ${JSON.stringify(f.evidence)}`);
}
if (!findings.length) console.log("   (none)");

hr("3) Server-side blur gate -- what a FREE user receives");
const teasers = lockedTeasersForPlatform(detection.platform);
const freeView = serializeFindings(findings, "free");
console.log(`   ${freeView.length} unlocked findings + ${teasers.length} locked teasers`);
console.log("   locked teaser examples (no evidence/fix sent to client):");
for (const t of teasers.slice(0, 3)) {
  console.log(`     [LOCKED ${t.severity.toUpperCase()}] ${t.title} -- ${t.impactOneline}`);
}

hr("4) Same findings re-gated for a DEEP user -- now unlocked");
const deepView = serializeFindings(findings, "deep");
const sample = deepView[0] as any;
if (sample) {
  console.log(`   ${sample.title}`);
  console.log(`     unlocked: ${sample.unlocked}`);
  console.log(`     fixPrompt now present: ${Boolean(sample.fixPrompt)}`);
}

hr("Proof of the blur boundary");
const lockedForFree = serializeFindings(
  [{ ...findings[0], tierRequired: "deep" } as PatternFinding],
  "free"
)[0] as any;
console.log(`   A deep-tier finding shown to a free user includes evidence? ${"evidence" in lockedForFree}`);
console.log(`   -> gated fields are simply absent from the payload, not hidden in the DOM.`);
console.log("\n\x1b[1m=== demo complete ===\x1b[0m");
