import crypto from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { fetchDoc, normalizeTarget } from "../checks/http";

// Tiered ownership verification (plan item 5):
//  - Free scan: click-through attestation (handled at the route, no proof needed).
//  - Deep / Continuous: prove control of the domain before any aggressive probing.
//
// Supported proofs (least friction first):
//  1. well_known: GET https://domain/.well-known/thugir-verify.txt == token
//  2. meta_tag:   <meta name="thugir-site-verification" content="token"> on the homepage
//  3. dns_txt:    TXT record "thugir-verify=token" on the domain

export type VerifyMethod = "meta_tag" | "dns_txt" | "well_known";

// Deterministic per-(user, domain) token so it is stable across reissues.
export function makeToken(userId: string, domain: string): string {
  const secret = process.env.WORKER_CALLBACK_SECRET || "dev-only-secret";
  return (
    "thugir-" +
    crypto.createHmac("sha256", secret).update(`${userId}:${domain}`).digest("hex").slice(0, 32)
  );
}

export function rootDomain(input: string): string {
  const u = normalizeTarget(input);
  return u.hostname.toLowerCase();
}

export async function verifyOwnership(
  domain: string,
  token: string,
  method: VerifyMethod
): Promise<{ verified: boolean; detail: string }> {
  switch (method) {
    case "well_known": {
      const doc = await fetchDoc(`https://${domain}/.well-known/thugir-verify.txt`, {
        maxBytes: 1024
      });
      const verified = doc.status === 200 && doc.body.trim() === token;
      return { verified, detail: verified ? "file matched" : `status ${doc.status}` };
    }
    case "meta_tag": {
      const doc = await fetchDoc(`https://${domain}/`, { maxBytes: 200_000 });
      const re = new RegExp(
        `<meta[^>]+name=["']thugir-site-verification["'][^>]+content=["']${token}["']`,
        "i"
      );
      const verified = re.test(doc.body);
      return { verified, detail: verified ? "meta tag matched" : "meta tag not found" };
    }
    case "dns_txt": {
      try {
        const records = await resolveTxt(domain);
        const flat = records.map((r) => r.join("")).join(" ");
        const verified = flat.includes(`thugir-verify=${token}`);
        return { verified, detail: verified ? "TXT matched" : "TXT not found" };
      } catch (e) {
        return { verified: false, detail: `dns error: ${(e as Error).message}` };
      }
    }
  }
}
