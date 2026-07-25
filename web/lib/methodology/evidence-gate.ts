/**
 * Evidence anti-hallucination gate — claims must appear verbatim in tool output.
 * Claims (flags, secrets, exploit proof) must appear verbatim in tool output.
 */

/** True if claimed text appears in captured tool evidence (case-sensitive first, then normalized). */
export function claimInEvidence(claim: string, toolOutputs: string[]): boolean {
  const c = (claim || "").trim();
  if (c.length < 4) return false;

  for (const out of toolOutputs) {
    if (!out) continue;
    if (out.includes(c)) return true;
    const norm = (s: string) => s.replace(/\s+/g, " ").trim().toLowerCase();
    if (norm(out).includes(norm(c))) return true;
  }
  return false;
}

/** Reject agent conclusions that cite flags/secrets not present in evidence. */
export function passesEvidenceGate(
  conclusion: string,
  toolOutputs: string[],
  opts?: { requireFlag?: boolean }
): boolean {
  if (!conclusion?.trim()) return false;

  const flagMatch = conclusion.match(/flag\{[^}]+\}/i) || conclusion.match(/FLAG\{[^}]+\}/);
  if (flagMatch) {
    return claimInEvidence(flagMatch[0], toolOutputs);
  }

  if (opts?.requireFlag) return false;

  // For non-flag conclusions, require at least one advance marker from tool output overlap
  const markers = [
    "sql",
    "xss",
    "unauthorized",
    "200",
    "token",
    "admin",
    "injection",
    "exposed",
    "cve-"
  ];
  const lower = conclusion.toLowerCase();
  const hasMarker = markers.some((m) => lower.includes(m));
  if (!hasMarker) return true; // descriptive finding without exploit claim

  return toolOutputs.some((o) => markers.some((m) => o.toLowerCase().includes(m)));
}

export const EVIDENCE_GATE_PROMPT = `EVIDENCE GATE (mandatory): Any flag, secret, or exploit proof you cite MUST appear verbatim in tool output you received this turn. If it does not appear in HTTP responses or command output, mark the finding as [unverified] — never invent proof.`;
