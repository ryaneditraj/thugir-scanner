import { fetchDoc, type FetchedDoc } from "./http";
import { ProbeCache } from "./probe-cache";

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
