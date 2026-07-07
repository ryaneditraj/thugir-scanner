import { getServiceSupabase } from "@/lib/supabase/server";
import { enqueueDeepScan } from "@/lib/queue/qstash";

export interface EnqueueDeepScanInput {
  userId: string;
  targetUrl: string;
  verifiedDomain?: boolean;
  monitorId?: string;
  previousScanId?: string | null;
}

// Create a queued deep scan row and publish to the worker via QStash.
export async function createAndEnqueueDeepScan(
  input: EnqueueDeepScanInput
): Promise<{ scanId: string }> {
  const svc = getServiceSupabase();
  const { data: scan, error } = await svc
    .from("scans")
    .insert({
      user_id: input.userId,
      target_url: input.targetUrl,
      tier: "deep",
      status: "queued",
      verified_domain: Boolean(input.verifiedDomain),
      monitor_id: input.monitorId ?? null
    })
    .select("id")
    .single();

  if (error || !scan?.id) {
    throw new Error(error?.message ?? "Could not create scan");
  }

  try {
    await enqueueDeepScan({
      scanId: scan.id,
      userId: input.userId,
      targetUrl: input.targetUrl,
      detectedPlatform: null,
      includeInjection: true,
      verifiedDomain: Boolean(input.verifiedDomain),
      monitorId: input.monitorId,
      previousScanId: input.previousScanId ?? undefined
    });
  } catch (e) {
    await svc.from("scans").update({ status: "failed", error: String(e) }).eq("id", scan.id);
    throw e;
  }

  return { scanId: scan.id };
}
