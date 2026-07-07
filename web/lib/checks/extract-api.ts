/** Pull same-origin API paths referenced in HTML/JS for read-only deep probes. */

export function extractApiPaths(text: string, limit = 10): string[] {
  const paths = new Set<string>();
  const patterns = [
    /["'`](\/api\/[a-z0-9_\-/.]+)["'`]/gi,
    /fetch\(\s*["'](\/api\/[^"'`?]+)["']/gi,
    /axios\.(?:get|post|put|delete|patch)\(\s*["'](\/api\/[^"'`?]+)["']/gi,
    /href=["'](\/api\/[^"'`?#]+)["']/gi
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      const p = m[1].split("?")[0].replace(/\/+$/, "") || m[1];
      if (p.includes("${") || p.includes("{{") || p.length > 80) continue;
      if (/\.(js|css|png|jpg|svg|ico|map)$/i.test(p)) continue;
      paths.add(p.startsWith("/") ? p : `/${p}`);
      if (paths.size >= limit * 2) break;
    }
  }
  return [...paths].slice(0, limit);
}
