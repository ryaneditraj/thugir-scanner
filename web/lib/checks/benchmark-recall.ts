/** Map scanner findings to benchmark oracle categories (docs/internal/power-loop/benchmarks.json). */

const SLUG_TO_BENCHMARK: Record<string, string[]> = {
  "sql-error-disclosure": ["sqli"],
  "post-login-sql-bypass": ["sqli", "auth_bypass"],
  "client-side-sql-evidence": ["sqli"],
  "client-side-nosql-evidence": ["sqli"],
  "client-side-xxe-evidence": ["sqli"],
  "client-side-api-security-lab-evidence": ["idor", "auth_bypass"],
  "unauthenticated-admin-endpoint": ["auth_bypass"],
  "security-question-disclosure": ["sensitive_data"],
  "juice-shop-forgotten-backup-disclosure": ["sensitive_data"],
  "juice-shop-leaked-api-key": ["sensitive_data"],
  "dangerous-html-sinks": ["xss"],
  "dom-eval-xss": ["xss"],
  "idor-sequential-ids": ["idor"],
  "spring-boot-actuator-exposed": ["misconfig"],
  "secret-resend": ["sensitive_data"],
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
