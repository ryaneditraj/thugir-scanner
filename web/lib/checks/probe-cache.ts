import { fetchDoc, toRawGithubusercontentUrl, type FetchedDoc } from "./http";

type FetchOpts = Parameters<typeof fetchDoc>[1];

const RETRYABLE_HEROKU_ERROR_RE = /Application Error|herokucdn\.com\/error-pages/i;

/** Cold-start Heroku stubs must not poison the probe cache for the rest of the scan. */
function isRetryableProbeResult(doc: FetchedDoc): boolean {
  if (doc.status === 0) return true;
  if (doc.status === 502 || doc.status === 503 || doc.status === 504) return true;
  if (RETRYABLE_HEROKU_ERROR_RE.test(doc.body)) return true;
  return false;
}

async function fetchWithGithackFallback(url: string, opts: FetchOpts): Promise<FetchedDoc> {
  const doc = await fetchDoc(url, opts);
  if (
    doc.body.length > 0 &&
    doc.status >= 200 &&
    doc.status < 400 &&
    !RETRYABLE_HEROKU_ERROR_RE.test(doc.body)
  ) {
    return doc;
  }
  const raw = toRawGithubusercontentUrl(url);
  if (!raw || raw === url) return doc;
  const alt = await fetchDoc(raw, opts);
  if (alt.status >= 200 && alt.status < 400 && alt.body.length > 0) return alt;
  return doc.status === 0 && alt.status > 0 ? alt : doc;
}

function cacheKey(url: string, opts: FetchOpts = {}): string {
  const method = opts.method ?? "GET";
  const body = opts.body ?? "";
  const hdr = opts.headers ? JSON.stringify(opts.headers) : "";
  const maxBytes = opts.maxBytes ?? "";
  const redirect = opts.redirect ?? "";
  return `${method}:${url}:${body}:${hdr}:${maxBytes}:${redirect}`;
}

/** Dedupes identical HTTP probes within a single scan (Cycle 16–17). */
export class ProbeCache {
  private readonly pending = new Map<string, Promise<FetchedDoc>>();

  get(url: string, opts: FetchOpts = {}): Promise<FetchedDoc> {
    const key = cacheKey(url, opts);
    let p = this.pending.get(key);
    if (!p) {
      p = fetchWithGithackFallback(url, opts).then((doc) => {
        if (isRetryableProbeResult(doc)) this.pending.delete(key);
        return doc;
      });
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
