import { fetchDoc, githackDeployBase, resolvePageAssetUrl, type FetchedDoc } from "./http";
import { ProbeCache } from "./probe-cache";

const ES_MODULE_IMPORT_RE = /\bfrom\s+["'](\.[^"']+)["']/g;

/** When githack serves index.html only, follow ES module imports to sibling .jsx/.ts sources. */
export function expandGithackModuleImports(
  scripts: FetchedDoc[],
  pageUrl: string,
  limit = 8
): string[] {
  const base = githackDeployBase(pageUrl);
  if (!base) return [];
  const out = new Set<string>();
  for (const s of scripts) {
    if (!s.body) continue;
    let m: RegExpExecArray | null;
    ES_MODULE_IMPORT_RE.lastIndex = 0;
    while ((m = ES_MODULE_IMPORT_RE.exec(s.body))) {
      const resolved = resolvePageAssetUrl(m[1], s.finalUrl || s.url);
      if (resolved) out.add(resolved);
    }
  }
  return [...out].slice(0, limit);
}

/** Fetch many script URLs in parallel batches (deduped via ProbeCache). */
export async function fetchScriptsBatched(
  urls: string[],
  opts: { maxBytes?: number; concurrency?: number; probe?: ProbeCache } = {}
): Promise<FetchedDoc[]> {
  const probe = opts.probe ?? new ProbeCache();
  const maxBytes = opts.maxBytes ?? 800_000;
  const concurrency = opts.concurrency ?? 4;
  if (urls.length === 0) return [];
  const map = await probe.getMany(urls, { maxBytes }, concurrency);
  return urls.map((u) => map.get(u)!).filter(Boolean);
}

/** Fetch crawl pages in parallel. */
export async function fetchPagesBatched(
  urls: string[],
  opts: { maxBytes?: number; concurrency?: number; probe?: ProbeCache } = {}
): Promise<FetchedDoc[]> {
  return fetchScriptsBatched(urls, { ...opts, maxBytes: opts.maxBytes ?? 600_000 });
}
