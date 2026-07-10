import type { PatternFinding, Severity } from "../patterns/types";
import type { VulnClawFinding } from "./types";

const SEV_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "low"
};

function normSeverity(raw?: string): Severity {
  if (!raw) return "medium";
  const k = raw.toLowerCase();
  return SEV_MAP[k] || "medium";
}

function slugFromTitle(title: string): string {
  return `vulnclaw-${title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .slice(0, 48)
    .replace(/-$/, "")}`;
}

/** Map VulnClaw agent findings into Thugir PatternFinding shape. */
export function mapVulnClawFindings(
  findings: VulnClawFinding[],
  target: string
): PatternFinding[] {
  const out: PatternFinding[] = [];

  for (const f of findings) {
    const title = (f.title || f.vuln_type || "Agent finding").trim();
    if (!title) continue;

    const evidence =
      (f.evidence as string) ||
      (f.proof as string) ||
      (f.description as string) ||
      "";
    const verified =
      f.verified === true || f.verification_status === "verified";

    out.push({
      patternSlug: slugFromTitle(title),
      category: (f.vuln_type as string) || "Agent detection",
      severity: normSeverity(f.severity as string),
      title,
      tierRequired: "deep",
      impactOneline: verified
        ? "Verified by VulnClaw agent with tool evidence."
        : "Candidate finding from VulnClaw agent — needs review.",
      evidence: {
        quote: evidence.slice(0, 500),
        location: (f.location as string) || target,
        agent: "vulnclaw",
        verified,
        verification_status: f.verification_status || "pending",
        description: (f.description as string) || title
      },
      confidence: verified ? 0.92 : 0.65,
      remediation: f.remediation
        ? { summary: String(f.remediation), steps: [] }
        : undefined,
      fixPrompt: f.remediation
        ? String(f.remediation)
        : `Fix the ${title} vulnerability found during agent penetration testing on ${target}.`
    });
  }

  return out;
}
