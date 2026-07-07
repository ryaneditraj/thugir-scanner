import { Client } from "@upstash/qstash";

// QStash is the durable job queue between the Next.js app (enqueues Deep Scan) and the
// Python worker (executes it). Using QStash means no always-on worker process on Vercel.

let client: Client | null = null;
function getClient(): Client {
  if (client) return client;
  const token = process.env.QSTASH_TOKEN;
  if (!token) throw new Error("QSTASH_TOKEN is not configured");
  client = new Client({ token });
  return client;
}

export interface DeepScanJob {
  scanId: string;
  userId: string;
  targetUrl: string;
  detectedPlatform: string | null;
  includeInjection: boolean;
  verifiedDomain?: boolean;
  monitorId?: string;
  previousScanId?: string;
}

// Publish a Deep Scan job. QStash will POST it (signed) to WORKER_URL and retry on failure.
export async function enqueueDeepScan(job: DeepScanJob): Promise<{ messageId: string }> {
  const workerUrl = process.env.WORKER_URL;
  if (!workerUrl) throw new Error("WORKER_URL is not configured");
  const res = await getClient().publishJSON({
    url: workerUrl,
    body: job,
    retries: 3,
    // The worker writes results straight to Supabase; this is fire-and-forget for the app.
    headers: { "Content-Type": "application/json" }
  });
  return { messageId: res.messageId };
}
