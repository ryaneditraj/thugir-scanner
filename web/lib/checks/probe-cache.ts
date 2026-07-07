import { fetchDoc, type FetchedDoc } from "./http";

type FetchOpts = Parameters<typeof fetchDoc>[1];

function cacheKey(url: string, opts: FetchOpts = {}): string {
  const method = opts.method ?? "GET";
  const body = opts.body ?? "";
  const hdr = opts.headers ? JSON.stringify(opts.headers) : "";
  const redirect = opts.redirect ?? "follow";
  return `${method}:${url}:${body}:${hdr}:${redirect}`;
}

/** Dedupes identical HTTP probes within a single scan (Cycle 16–17). */
export class ProbeCache {
  private readonly pending = new Map<string, Promise<FetchedDoc>>();

  get(url: string, opts: FetchOpts = {}): Promise<FetchedDoc> {
    const key = cacheKey(url, opts);
    let p = this.pending.get(key);
    if (!p) {
      p = fetchDoc(url, opts);
      this.pending.set(key, p);
    }
    return p;
  }

  /** Run up to `concurrency` probes in parallel (Cycle 13–15). */
  async getMany(urls: string[], opts: FetchOpts = {}, concurrency = 4): Promise<Map<string, FetchedDoc>> {
    const out = new Map<string, FetchedDoc>();
    for (let i = 0; i < urls.length; i += concurrency) {
      const batch = urls.slice(i, i + concurrency);
      const docs = await Promise.all(batch.map((u) => this.get(u, opts)));
      batch.forEach((u, j) => out.set(u, docs[j]!));
    }
    return out;
  }

  get size(): number {
    return this.pending.size;
  }
}
