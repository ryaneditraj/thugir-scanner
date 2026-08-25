import type { ProbeCache } from "./probe-cache";

/** Fetch Bluesky/Mastodon/public social feeds from Juice Shop config (Leaked API Key / Resend oracle corpus). */
export async function fetchJuiceShopSocialFeedBodies(
  configBody: string,
  probe: ProbeCache
): Promise<string> {
  const chunks: string[] = [];
  try {
    const social = (
      JSON.parse(configBody) as { config?: { application?: { social?: Record<string, string | null> } } }
    )?.config?.application?.social;
    if (!social) return "";

    const bskyUrl = social.blueSkyUrl;
    if (bskyUrl) {
      const handle = bskyUrl.match(/profile\/([^/?#]+)/i)?.[1];
      if (handle) {
        let cursor: string | undefined;
        for (let page = 0; page < 5; page++) {
          const feedUrl = `https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=${encodeURIComponent(handle)}&limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
          const doc = await probe.get(feedUrl, { maxBytes: 96_000, timeoutMs: 12000 });
          if (doc.status < 200 || doc.status >= 400) break;
          chunks.push(doc.body);
          try {
            const parsed = JSON.parse(doc.body) as { cursor?: string };
            cursor = parsed.cursor;
            if (!cursor) break;
          } catch {
            break;
          }
        }
        const searchUrl = `https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=${encodeURIComponent(`from:${handle}`)}&limit=50`;
        const searchDoc = await probe.get(searchUrl, { maxBytes: 96_000, timeoutMs: 12000 });
        if (searchDoc.status >= 200 && searchDoc.status < 400) chunks.push(searchDoc.body);
        for (const term of ["resend", "apikey", "re_"]) {
          const scopedSearchUrl = `https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=${encodeURIComponent(`from:${handle} ${term}`)}&limit=50`;
          const scopedDoc = await probe.get(scopedSearchUrl, { maxBytes: 96_000, timeoutMs: 12000 });
          if (scopedDoc.status >= 200 && scopedDoc.status < 400) chunks.push(scopedDoc.body);
        }
      }
    }

    const mastodonUrl = social.mastodonUrl;
    if (mastodonUrl) {
      const match = mastodonUrl.match(/^(https?:\/\/[^/]+)\/@([^/?#]+)/i);
      if (match) {
        const [, instance, acct] = match;
        const lookupUrl = `${instance}/api/v1/accounts/lookup?acct=${encodeURIComponent(acct)}`;
        const lookup = await probe.get(lookupUrl, { maxBytes: 4096, timeoutMs: 12000 });
        if (lookup.status >= 200 && lookup.status < 400) {
          const idMatch = lookup.body.match(/"id"\s*:\s*"(\d+)"/);
          if (idMatch) {
            let maxId: string | null = null;
            for (let page = 0; page < 5; page++) {
              const statusesUrl = `${instance}/api/v1/accounts/${idMatch[1]}/statuses?limit=40${maxId ? `&max_id=${maxId}` : ""}`;
              const statuses = await probe.get(statusesUrl, { maxBytes: 96_000, timeoutMs: 12000 });
              if (statuses.status < 200 || statuses.status >= 400) break;
              chunks.push(statuses.body);
              try {
                const posts = JSON.parse(statuses.body) as Array<{ id?: string }>;
                if (!Array.isArray(posts) || posts.length === 0) break;
                const lastId = posts[posts.length - 1]?.id;
                if (!lastId || posts.length < 40) break;
                maxId = lastId;
              } catch {
                break;
              }
            }
            for (const term of ["resend", "re_", "apikey"]) {
              const searchUrl = `${instance}/api/v2/search?q=${encodeURIComponent(term)}&account_id=${idMatch[1]}&type=statuses&limit=40`;
              const searchDoc = await probe.get(searchUrl, { maxBytes: 96_000, timeoutMs: 12000 });
              if (searchDoc.status >= 200 && searchDoc.status < 400) chunks.push(searchDoc.body);
            }
          }
        }
      }
    }

    const redditUrl = social.redditUrl;
    if (redditUrl) {
      const subMatch = redditUrl.match(/reddit\.com\/r\/([^/?#]+)/i);
      if (subMatch) {
        const sub = encodeURIComponent(subMatch[1]!);
        const redditHeaders = { "User-Agent": "Mozilla/5.0 (compatible; ThugirScanner/1.0)" };
        let after: string | undefined;
        for (let page = 0; page < 4; page++) {
          const feedUrl = `https://www.reddit.com/r/${sub}/new.json?limit=100${after ? `&after=${encodeURIComponent(after)}` : ""}`;
          const feed = await probe.get(feedUrl, {
            maxBytes: 96_000,
            timeoutMs: 12000,
            headers: redditHeaders
          });
          if (feed.status < 200 || feed.status >= 400) break;
          chunks.push(feed.body);
          try {
            const parsed = JSON.parse(feed.body) as {
              data?: { after?: string; children?: unknown[] };
            };
            after = parsed.data?.after;
            if (!after || !parsed.data?.children?.length) break;
          } catch {
            break;
          }
        }
        // old.reddit JSON search fallback when www.reddit blocks cloud egress.
        for (const term of ["resend", "re_", "apikey"]) {
          const oldSearchUrl = `https://old.reddit.com/r/${sub}/search.json?q=${encodeURIComponent(term)}&restrict_sr=on&sort=new&limit=100`;
          const oldSearch = await probe.get(oldSearchUrl, {
            maxBytes: 96_000,
            timeoutMs: 12000,
            headers: redditHeaders
          });
          if (oldSearch.status >= 200 && oldSearch.status < 400) chunks.push(oldSearch.body);
        }
      }
    }

    const twitterUrl = social.twitterUrl;
    if (twitterUrl) {
      const handle = twitterUrl.match(/twitter\.com\/([^/?#]+)/i)?.[1];
      if (handle) {
        const syndicationUrl = `https://syndication.twitter.com/srv/timeline-profile/screen-name/${encodeURIComponent(handle)}`;
        const tw = await probe.get(syndicationUrl, {
          maxBytes: 96_000,
          timeoutMs: 12000,
          headers: { "User-Agent": "Mozilla/5.0 (compatible; ThugirScanner/1.0)" }
        });
        if (tw.status >= 200 && tw.status < 400) chunks.push(tw.body);
      }
    }

    const facebookUrl = social.facebookUrl;
    if (facebookUrl) {
      const fb = await probe.get(facebookUrl, {
        maxBytes: 96_000,
        timeoutMs: 12000,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; ThugirScanner/1.0)" }
      });
      if (fb.status >= 200 && fb.status < 400) chunks.push(fb.body);
    }

    const pressKitUrl = social.pressKitUrl;
    if (pressKitUrl) {
      const pressKit = await probe.get(pressKitUrl, {
        maxBytes: 96_000,
        timeoutMs: 12000,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; ThugirScanner/1.0)" }
      });
      if (pressKit.status >= 200 && pressKit.status < 400) chunks.push(pressKit.body);
    }

    const nftUrl = social.nftUrl;
    if (nftUrl) {
      const nft = await probe.get(nftUrl, {
        maxBytes: 96_000,
        timeoutMs: 12000,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; ThugirScanner/1.0)" }
      });
      if (nft.status >= 200 && nft.status < 400) chunks.push(nft.body);
    }

    const slackUrl = social.slackUrl;
    if (slackUrl) {
      const slack = await probe.get(slackUrl, {
        maxBytes: 96_000,
        timeoutMs: 12000,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; ThugirScanner/1.0)" }
      });
      if (slack.status >= 200 && slack.status < 400) chunks.push(slack.body);
    }

    for (const tag of ["juiceshop", "resend", "juice-shop"]) {
      const tagUrl = `https://fosstodon.org/api/v1/timelines/tag/${encodeURIComponent(tag)}?limit=80`;
      const tagDoc = await probe.get(tagUrl, { maxBytes: 96_000, timeoutMs: 12000 });
      if (tagDoc.status >= 200 && tagDoc.status < 400) chunks.push(tagDoc.body);
    }
  } catch {
    /* ignore malformed config or feed fetch errors */
  }
  return chunks.join("\n");
}

export const JUICE_SHOP_RESEND_KEY_RE = /re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}/g;

export function extractJuiceShopResendKeys(corpus: string): string[] {
  const raw = corpus.match(JUICE_SHOP_RESEND_KEY_RE) ?? [];
  const seen = new Set<string>();
  for (const m of raw) {
    if (/WEBPACK|__WEBPACK|MODULE/i.test(m)) continue;
    seen.add(m);
  }
  return [...seen];
}
