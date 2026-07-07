// Pattern library type system.
//
// A Pattern is the unit of the product's IP: a known, recurring vulnerability that a
// specific AI app-builder ("vibe-coding" tool) tends to ship. Patterns are designed to
// be expressible as DATA so new ones can be added as rows in the `patterns` table without
// a redeploy. The detector_kind tells the engine how to evaluate detector_config.
//
// Keep this in sync with the `patterns` table in supabase/migrations/0001_init.sql.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Tier = "free" | "deep" | "continuous";

export type Platform =
  | "supabase"
  | "firebase"
  | "lovable"
  | "bolt"
  | "v0"
  | "replit"
  | "cursor"
  | "windsurf"
  | "base44"
  | "claude"
  | "copilot"
  | "generic";

export type DetectorKind = "secret_regex" | "http_probe" | "rule_ref";

// secret_regex: scan fetched JS/HTML bodies for a high-precision credential pattern.
export interface SecretRegexConfig {
  // Source regex (string form so it can live in the DB). Compiled with the `gi` flags.
  regex: string;
  // Optional second regex the match must also satisfy (reduces FPs, e.g. length/charset).
  validate?: string;
  // Human label of what leaked, e.g. "Stripe secret key".
  secretName: string;
  // If true this is unambiguously a server secret that must never reach the client.
  serverOnly?: boolean;
}

// http_probe: fetch one or more fixed paths and assert something about the response.
export interface HttpProbeConfig {
  // Paths appended to the origin, e.g. ["/.env", "/.git/HEAD"].
  paths: string[];
  // Match condition. "exposed" => any 2xx with non-HTML body is a hit.
  expect:
    | { kind: "status_2xx_non_html" }
    | { kind: "status_2xx" }
    | { kind: "body_contains"; needle: string }
    | { kind: "body_regex"; regex: string }
    | { kind: "header_absent"; header: string }
    | { kind: "header_present"; header: string };
  // Cap on bytes read from the body (free tier stays cheap).
  maxBytes?: number;
}

// rule_ref: defers to a named TS check in lib/checks (used for multi-signal logic like
// the Supabase RLS probe or the webhook-signature heuristic).
export interface RuleRefConfig {
  rule: string; // key in lib/checks registry
  options?: Record<string, unknown>;
}

export type DetectorConfig = SecretRegexConfig | HttpProbeConfig | RuleRefConfig;

export interface Pattern {
  slug: string;
  platform: Platform;
  category: string;
  severityDefault: Severity;
  title: string;
  description: string;
  impactOneline: string; // founder-readable "why this matters", ALWAYS shown
  detectorKind: DetectorKind;
  detectorConfig: DetectorConfig;
  tierRequired: Tier; // free => full result shown; deep => locked card on free scan
  remediation?: {
    summary: string;
    steps: string[];
  };
  // Pre-formatted text the user pastes back into their AI builder to fix it.
  fixPrompt?: string;
  version: number;
  enabled: boolean;
}

// A finding produced by evaluating a pattern against a target.
export interface PatternFinding {
  patternSlug: string;
  category: string;
  title: string;
  severity: Severity;
  tierRequired: Tier;
  impactOneline: string;
  maxDamageOneline?: string; // worst-case business outcome if exploited
  evidence: Record<string, unknown>;
  remediation?: Pattern["remediation"];
  fixPrompt?: string;
  confidence: number; // 0..1
}
