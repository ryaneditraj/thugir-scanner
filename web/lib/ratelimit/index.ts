import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Free-tier abuse control. Sliding windows keyed by user id (preferred) and by IP.
// Generous enough for honest use, tight enough to deter drive-by scanning.

let redis: Redis | null = null;
function getRedis(): Redis | null {
  if (redis) return redis;
  const u = process.env.UPSTASH_REDIS_REST_URL;
  const t = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!u || !t) return null;
  redis = new Redis({ url: u, token: t });
  return redis;
}

function limiter(prefix: string, max: number, window: `${number} ${"s" | "m" | "h" | "d"}`) {
  const r = getRedis();
  if (!r) return null;
  return new Ratelimit({ redis: r, limiter: Ratelimit.slidingWindow(max, window), prefix });
}

export interface LimitDecision {
  ok: boolean;
  remaining: number;
  reset: number;
}

// Free scans: per user/day and per IP/hour.
export async function checkFreeScanLimit(userId: string, ip: string): Promise<LimitDecision> {
  const perUser = limiter("free:user", 5, "1 d");
  const perIp = limiter("free:ip", 10, "1 h");
  if (!perUser || !perIp) return { ok: true, remaining: -1, reset: 0 }; // fail-open in dev only
  const [u, i] = await Promise.all([perUser.limit(userId), perIp.limit(`ip:${ip}`)]);
  const ok = u.success && i.success;
  return { ok, remaining: Math.min(u.remaining, i.remaining), reset: Math.max(u.reset, i.reset) };
}

// Admin login attempts: tight per-IP throttle.
export async function checkAdminLoginLimit(ip: string): Promise<LimitDecision> {
  const l = limiter("admin:login", 5, "10 m");
  if (!l) return { ok: true, remaining: -1, reset: 0 };
  const r = await l.limit(`ip:${ip}`);
  return { ok: r.success, remaining: r.remaining, reset: r.reset };
}
