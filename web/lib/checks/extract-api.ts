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

/** External API hosts referenced in SPA bundles (axios baseURL, Railway/Heroku backends). */
export function extractExternalApiBases(text: string, pageOrigin: string, limit = 4): string[] {
  const own = new URL(pageOrigin).origin;
  const bases = new Set<string>();
  const patterns = [
    /baseURL:\s*["'](https?:\/\/[^"']+)["']/gi,
    /create\(\{\s*baseURL:\s*["'](https?:\/\/[^"']+)["']/gi,
    /["'](https?:\/\/[a-z0-9.-]+(?:\.railway\.app|\.herokuapp\.com|\.onrender\.com|\.fly\.dev|apisec\.ai))(?:\/api)?["']/gi
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      let raw = m[1].replace(/\/+$/, "");
      if (/\/api$/i.test(raw)) raw = raw.replace(/\/api$/i, "");
      try {
        const origin = new URL(raw).origin;
        if (origin !== own) bases.add(origin);
      } catch {
        /* ignore */
      }
      if (bases.size >= limit * 2) break;
    }
  }
  return [...bases].slice(0, limit);
}

/** Build absolute probe URLs from same-origin paths and discovered external API hosts. */
export function buildApiProbeUrls(
  paths: string[],
  pageOrigin: string,
  externalBases: string[],
  limit = 16
): string[] {
  const urls: string[] = [];
  const seen = new Set<string>();
  const origins = [pageOrigin, ...externalBases];
  for (const origin of origins) {
    for (const path of paths) {
      const url = new URL(path, origin).toString();
      if (seen.has(url)) continue;
      seen.add(url);
      urls.push(url);
      if (urls.length >= limit) return urls;
    }
  }
  return urls;
}
