import { NextRequest } from "next/server";
import { Receiver } from "@upstash/qstash";

// Vercel Cron sends Authorization: Bearer <CRON_SECRET>.
// QStash scheduled jobs send Upstash-Signature.
export async function authorizeCron(req: NextRequest, bodyText?: string): Promise<boolean> {
  const cronSecret = process.env.CRON_SECRET;
  const auth = req.headers.get("authorization");
  if (cronSecret && auth === `Bearer ${cronSecret}`) return true;

  const qstashSig = req.headers.get("upstash-signature");
  if (qstashSig && bodyText) {
    const current = process.env.QSTASH_CURRENT_SIGNING_KEY;
    const next = process.env.QSTASH_NEXT_SIGNING_KEY;
    if (current && next) {
      try {
        const receiver = new Receiver({ currentSigningKey: current, nextSigningKey: next });
        await receiver.verify({ signature: qstashSig, body: bodyText });
        return true;
      } catch {
        return false;
      }
    }
  }

  // Local dev: allow unsigned when explicitly enabled.
  if (process.env.DEV_MODE === "1" && process.env.ALLOW_UNSIGNED_CRON === "1") return true;
  return false;
}
