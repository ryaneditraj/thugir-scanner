/** Map scanner findings to benchmark oracle categories (docs/internal/power-loop/benchmarks.json). */

const SLUG_TO_BENCHMARK: Record<string, string[]> = {
  "sql-error-disclosure": ["sqli"],
  "unauthenticated-admin-endpoint": ["auth_bypass"],
  "dangerous-html-sinks": ["xss"],
  "idor-sequential-ids": ["idor"],
  "vibe-unauthenticated-api-routes": ["idor", "sensitive_data"]
};

const CATEGORY_FALLBACK: Record<string, string[]> = {
  "Security misconfiguration": ["misconfig"],
  "Exposed secret": ["sensitive_data"],
  "Broken access control": ["idor"],
  "Broken authentication": ["auth_bypass"],
  Injection: ["sqli"],
  "Cross-site scripting": ["xss"]
};

export function benchmarkCategoriesForFinding(slug: string, category: string): string[] {
  if (SLUG_TO_BENCHMARK[slug]) return SLUG_TO_BENCHMARK[slug];
  return CATEGORY_FALLBACK[category] ?? [];
}

export function computeBenchmarkRecall(
  findings: Array<{ slug: string; category: string }>,
  expected: string[]
): { categories_expected: number; categories_hit: number; gap: string[]; hit: string[] } {
  const hitSet = new Set<string>();
  for (const f of findings) {
    for (const c of benchmarkCategoriesForFinding(f.slug, f.category)) hitSet.add(c);
  }
  const hit = expected.filter((c) => hitSet.has(c));
  const gap = expected.filter((c) => !hitSet.has(c));
  return {
    categories_expected: expected.length,
    categories_hit: hit.length,
    gap,
    hit
  };
}
