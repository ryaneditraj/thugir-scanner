/**
 * Crypto toolkit for JWT decode and token extraction in web scans.
 */
import { createHash } from "node:crypto";

export function base64Decode(input: string): { ok: boolean; value: string } {
  try {
    const cleaned = input.trim().replace(/-/g, "+").replace(/_/g, "/");
    const pad = cleaned + "=".repeat((4 - (cleaned.length % 4)) % 4);
    const raw = Buffer.from(pad, "base64").toString("utf8");
    return { ok: true, value: raw };
  } catch {
    return { ok: false, value: "" };
  }
}

export function urlDecode(input: string, depth = 2): string {
  let cur = input;
  for (let i = 0; i < depth; i++) {
    try {
      const next = decodeURIComponent(cur.replace(/\+/g, " "));
      if (next === cur) break;
      cur = next;
    } catch {
      break;
    }
  }
  return cur;
}

export function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  const parts = token.trim().split(".");
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(base64Decode(parts[0]).value) as Record<string, unknown>;
    const payload = JSON.parse(base64Decode(parts[1]).value) as Record<string, unknown>;
    if (!header || !payload || typeof header !== "object" || typeof payload !== "object") return null;
    return { header, payload };
  } catch {
    return null;
  }
}

/** Extract JWT-like tokens from JS/HTML text. */
export function extractJwtCandidates(text: string, limit = 5): string[] {
  const re = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,43}/g;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) && out.length < limit) {
    if (!out.includes(m[0])) out.push(m[0]);
  }
  return out;
}

export function md5Hex(input: string): string {
  return createHash("md5").update(input).digest("hex");
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}
