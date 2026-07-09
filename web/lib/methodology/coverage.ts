/**
 * Per-target coverage memory — what was tested (CyberStrike coverage-note pattern).
 * Persisted in scan metadata / power-loop results for learning loops.
 */
export type VulnClass =
  | "idor"
  | "authz"
  | "authn"
  | "injection"
  | "xss"
  | "ssrf"
  | "secrets"
  | "misconfig"
  | "api"
  | "other";

export type CoverageVerdict = "vulnerable" | "clean" | "skipped" | "not_applicable";

export interface CoverageNote {
  asset: string;
  class: VulnClass;
  scope: "wide" | "local";
  verdict: CoverageVerdict;
  note: string;
  tested_at: string;
}

export interface CoverageState {
  notes: CoverageNote[];
}

export function recordCoverage(state: CoverageState, note: CoverageNote): CoverageState {
  const key = `${note.scope}:${note.asset}:${note.class}`;
  const filtered = state.notes.filter(
    (n) => `${n.scope}:${n.asset}:${n.class}` !== key
  );
  return { notes: [...filtered, note] };
}

export function missingClasses(state: CoverageState, asset: string, expected: VulnClass[]): VulnClass[] {
  const tested = new Set(
    state.notes.filter((n) => n.asset === asset || n.scope === "wide").map((n) => n.class)
  );
  return expected.filter((c) => !tested.has(c));
}

/** OWASP web app classes to cover per origin (oracle checklist). */
export const DEFAULT_WEB_CLASSES: VulnClass[] = [
  "injection",
  "xss",
  "idor",
  "authz",
  "authn",
  "ssrf",
  "secrets",
  "misconfig",
  "api"
];
