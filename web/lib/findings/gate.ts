// Server-side tier gate (the blur mechanic). This is the ONLY thing that decides which
// finding fields a caller is allowed to receive. Gated fields for locked findings are never
// serialized to the client - not hidden via CSS, not present in the DOM.

import type { PatternFinding, Tier } from "../patterns/types";

const TIER_RANK: Record<Tier, number> = { free: 0, deep: 1, continuous: 2 };

export interface VisibleFinding {
  patternSlug: string;
  category: string;
  title: string;
  severity: PatternFinding["severity"];
  tierRequired: Tier;
  impactOneline: string;
  maxDamageOneline?: string;
  unlocked: boolean;
  // Present only when unlocked:
  evidence?: Record<string, unknown>;
  remediation?: PatternFinding["remediation"];
  fixPrompt?: string;
  confidence?: number;
}

export function isEntitled(userTier: Tier, required: Tier): boolean {
  return TIER_RANK[userTier] >= TIER_RANK[required];
}

// Builder names are confidential. Strip any leading AI-builder identifier from slugs before
// they leave the server, so the public API/DOM never reveals which builder a pattern targets.
// Internal detection + storage keep the real slug; this only affects outward serialization.
const BUILDER_PREFIX = /^(lovable|bolt|v0|replit|cursor|windsurf|base44)-/;
export function publicSlug(slug: string): string {
  return slug.replace(BUILDER_PREFIX, "");
}

// Serialize a finding for a user at a given tier. Locked findings return ONLY the teaser
// fields. This function is the trust boundary; callers must not bypass it.
export function serializeFinding(f: PatternFinding, userTier: Tier): VisibleFinding {
  const unlocked = isEntitled(userTier, f.tierRequired);
  const base: VisibleFinding = {
    patternSlug: publicSlug(f.patternSlug),
    category: f.category,
    title: f.title,
    severity: f.severity,
    tierRequired: f.tierRequired,
    impactOneline: f.impactOneline,
    unlocked
  };
  if (!unlocked) return base;
  return {
    ...base,
    maxDamageOneline: f.maxDamageOneline,
    evidence: f.evidence,
    remediation: f.remediation,
    fixPrompt: f.fixPrompt,
    confidence: f.confidence
  };
}

export function serializeFindings(findings: PatternFinding[], userTier: Tier): VisibleFinding[] {
  return findings.map((f) => serializeFinding(f, userTier));
}

// Shape used for a row coming from the `findings` table (DB-stored findings).
export interface DbFindingRow {
  id: string;
  scan_id: string;
  category: string;
  title: string;
  severity: PatternFinding["severity"];
  tier_required: Tier;
  impact_oneline: string;
  evidence_json: Record<string, unknown> | null;
  remediation_json: PatternFinding["remediation"] | null;
  fix_prompt: string | null;
  confidence: number;
  status: string;
}

export function serializeDbFinding(row: DbFindingRow, userTier: Tier) {
  const unlocked = isEntitled(userTier, row.tier_required);
  const base = {
    id: row.id,
    scanId: row.scan_id,
    category: row.category,
    title: row.title,
    severity: row.severity,
    tierRequired: row.tier_required,
    impactOneline: row.impact_oneline,
    status: row.status,
    unlocked
  };
  if (!unlocked) return base;
  const maxFromEvidence =
    row.evidence_json && typeof row.evidence_json.maxDamageOneline === "string"
      ? row.evidence_json.maxDamageOneline
      : undefined;
  return {
    ...base,
    maxDamageOneline: maxFromEvidence,
    evidence: row.evidence_json,
    remediation: row.remediation_json,
    fixPrompt: row.fix_prompt,
    confidence: row.confidence
  };
}
