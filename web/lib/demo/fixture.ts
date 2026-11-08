// In-memory fixture for the labeled sample. No HTTP. The strings below are invented so the
// free-tier detectors have something to match. They are not credentials from a real app.

import type { FetchedDoc } from "../checks/http";
import { RULES, type RuleContext } from "../checks/registry";
import type { ProbeCache } from "../checks/probe-cache";
import { scanSecret } from "../checks/runner";
import { detectPlatform } from "../detect";
import { serializeFindings, type VisibleFinding } from "../findings/gate";
import { findPattern, lockedTeasersForPlatform, patternsForTier, STATIC_PATTERNS } from "../patterns";
import type { PatternFinding } from "../patterns/types";

export const FIXTURE_URL = "https://synthetic.invalid/fixture";
export const FIXTURE_LABEL =
  "Synthetic fixture. The page and secrets below are invented. The findings are what the free-tier detectors returned. Nothing was fetched.";

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// Decodes to role service_role. The signature is filler and is not a real HMAC.
const SERVICE_ROLE_JWT = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({
  iss: "supabase",
  role: "service_role",
  fixture: "synthetic"
})}.synthetic-signature-not-a-real-key`;

export const FIXTURE_HTML = `<!doctype html>
<html><head>
  <meta name="generator" content="gptengineer / lovable.dev">
  <!-- SYNTHETIC FIXTURE. Not a deployed application. Do not treat these strings as live secrets. -->
</head><body>
<script>
  const SUPABASE_URL = "https://synthetic-project.supabase.co";
  const SUPABASE_SERVICE_ROLE = "${SERVICE_ROLE_JWT}";
  const FIREBASE = { apiKey: "AIzaSyA-synthetic-fixture-key-0123456789abc" };
</script>
</body></html>`;

const NO_FETCH = {
  async get(): Promise<FetchedDoc> {
    throw new Error("The synthetic fixture scan does not fetch.");
  },
  async getMany(): Promise<Map<string, FetchedDoc>> {
    throw new Error("The synthetic fixture scan does not fetch.");
  }
} as unknown as ProbeCache;

function fixtureDoc(): FetchedDoc {
  return {
    url: FIXTURE_URL,
    finalUrl: FIXTURE_URL,
    status: 200,
    ok: true,
    headers: { "content-type": "text/html" },
    setCookies: [],
    body: FIXTURE_HTML,
    truncated: false
  };
}

export interface FixtureScan {
  synthetic: true;
  label: string;
  target: string;
  detectedPlatform: string | null;
  signals: string[];
  findings: VisibleFinding[];
  locked: { checkCount: number; categories: string[] };
  librarySize: number;
  definedPatterns: number;
  freeChecks: number;
}

export async function runSyntheticFixtureScan(): Promise<FixtureScan & { rawFindings: PatternFinding[] }> {
  const home = fixtureDoc();
  const detection = detectPlatform(home, FIXTURE_HTML);
  const findings: PatternFinding[] = [];
  const seen = new Set<string>();

  for (const pattern of patternsForTier("free")) {
    if (pattern.detectorKind !== "secret_regex") continue;
    const hit = scanSecret(pattern, FIXTURE_HTML);
    if (hit && hit.confidence >= 0.8 && !seen.has(hit.patternSlug)) {
      seen.add(hit.patternSlug);
      findings.push(hit);
    }
  }

  const headerPattern = findPattern("missing-security-headers");
  const headerRule = RULES.securityHeaders;
  if (headerPattern && headerRule) {
    const ctx: RuleContext = {
      origin: "https://synthetic.invalid",
      scanUrl: FIXTURE_URL,
      home,
      scripts: [],
      combined: FIXTURE_HTML,
      probe: NO_FETCH
    };
    const res = await headerRule(ctx);
    if (res.fired && res.confidence >= 0.8) {
      findings.push({
        patternSlug: headerPattern.slug,
        category: headerPattern.category,
        title: headerPattern.title,
        severity: headerPattern.severityDefault,
        tierRequired: headerPattern.tierRequired,
        impactOneline: headerPattern.impactOneline,
        evidence: res.evidence,
        remediation: headerPattern.remediation,
        fixPrompt: headerPattern.fixPrompt,
        confidence: res.confidence
      });
    }
  }

  const teasers = lockedTeasersForPlatform(detection.platform);
  const categories = Array.from(new Set(teasers.map((t) => t.category)));
  return {
    synthetic: true,
    label: FIXTURE_LABEL,
    target: FIXTURE_URL,
    detectedPlatform: detection.platform,
    signals: detection.signals,
    findings: serializeFindings(findings, "free"),
    rawFindings: findings,
    locked: { checkCount: teasers.length, categories },
    librarySize: STATIC_PATTERNS.filter((p) => p.enabled).length,
    definedPatterns: STATIC_PATTERNS.length,
    freeChecks: patternsForTier("free").length
  };
}
