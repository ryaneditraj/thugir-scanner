import type { Pattern, Platform, Tier } from "./types";
import { supabasePatterns } from "./supabase";
import { firebasePatterns } from "./firebase";
import { secretPatterns, twilioCredentialPattern } from "./secrets";
import { genericPatterns } from "./generic";
import {
  lovablePatterns,
  boltPatterns,
  v0Patterns,
  replitPatterns,
  cursorPatterns,
  windsurfPatterns,
  stackPatterns
} from "./builders";
import { vibecodePatterns } from "./vibecode";
import { convexPatterns } from "./convex";
import { publicSlug } from "../findings/gate";

export * from "./types";

// Static (code-defined) library. This is the canonical seed; the `patterns` table in
// Supabase can extend/override at runtime (see loadPatterns) so new patterns ship as data.
// Moat: these encode what vibe-coding scaffolds ship wrong — not a generic CVE list.
export const STATIC_PATTERNS: Pattern[] = [
  ...secretPatterns,
  twilioCredentialPattern,
  ...genericPatterns,
  ...supabasePatterns,
  ...firebasePatterns,
  ...convexPatterns,
  ...vibecodePatterns,
  ...lovablePatterns,
  ...boltPatterns,
  ...v0Patterns,
  ...replitPatterns,
  ...cursorPatterns,
  ...windsurfPatterns,
  ...stackPatterns
];

export function patternsForTier(tier: Tier, all: Pattern[] = STATIC_PATTERNS): Pattern[] {
  // free scan runs only free-tier checks; locked deep cards are derived separately.
  if (tier === "free") return all.filter((p) => p.enabled && p.tierRequired === "free");
  return all.filter((p) => p.enabled);
}

export function patternsForPlatform(
  platform: Platform,
  all: Pattern[] = STATIC_PATTERNS
): Pattern[] {
  return all.filter((p) => p.enabled && (p.platform === platform || p.platform === "generic"));
}

export function findPattern(slug: string, all: Pattern[] = STATIC_PATTERNS): Pattern | undefined {
  return all.find((p) => p.slug === slug);
}

// Deep-tier patterns are surfaced on the free scan as locked teaser cards (title + severity +
// category + one-line impact only). Full details are never sent to a free user.
export function lockedTeasersForPlatform(
  platform: Platform | null,
  all: Pattern[] = STATIC_PATTERNS
) {
  return all
    .filter((p) => p.enabled && p.tierRequired !== "free")
    .filter((p) => !platform || p.platform === platform || p.platform === "generic")
    .map((p) => ({
      patternSlug: publicSlug(p.slug),
      category: p.category,
      title: p.title,
      severity: p.severityDefault,
      tierRequired: p.tierRequired,
      impactOneline: p.impactOneline
    }));
}
