import { getServiceSupabase } from "@/lib/supabase/server";
import { resolveUserTier } from "@/lib/entitlements";
import { createAndEnqueueDeepScan } from "@/lib/scans/enqueue";

export type DueMonitor = {
  id: string;
  user_id: string;
  target_url: string;
  interval_hours: number;
  last_scan_id: string | null;
};

export type TickResult = {
  checked: number;
  enqueued: number;
  skipped: number;
  errors: string[];
  mode?: "live" | "dry-run";
  note?: string;
};

function addHours(iso: string, hours: number): string {
  return new Date(new Date(iso).getTime() + hours * 3600_000).toISOString();
}

// Enqueue deep scans for monitors whose next_run_at is due.
export async function tickDueMonitors(limit = 20): Promise<TickResult> {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY?.trim()) {
    return {
      checked: 0,
      enqueued: 0,
      skipped: 0,
      errors: [],
      mode: "dry-run",
      note: "SUPABASE_SERVICE_ROLE_KEY unset — cron auth OK, DB tick skipped. Add service role from Supabase → Settings → API."
    };
  }
  const svc = getServiceSupabase();
  const now = new Date().toISOString();

  const { data: due, error } = await svc
    .from("monitors")
    .select("id, user_id, target_url, interval_hours, last_scan_id")
    .eq("enabled", true)
    .lte("next_run_at", now)
    .order("next_run_at", { ascending: true })
    .limit(limit);

  if (error) {
    return { checked: 0, enqueued: 0, skipped: 0, errors: [error.message] };
  }

  const monitors = (due ?? []) as DueMonitor[];
  const result: TickResult = { checked: monitors.length, enqueued: 0, skipped: 0, errors: [], mode: "live" };

  for (const monitor of monitors) {
    try {
      const tier = await resolveUserTier(monitor.user_id);
      if (tier !== "continuous") {
        await svc.from("monitors").update({ enabled: false }).eq("id", monitor.id);
        result.skipped += 1;
        continue;
      }

      const { data: verification } = await svc
        .from("domain_verifications")
        .select("verified")
        .eq("user_id", monitor.user_id)
        .eq("domain", new URL(monitor.target_url).hostname.toLowerCase())
        .eq("verified", true)
        .maybeSingle();

      const { scanId } = await createAndEnqueueDeepScan({
        userId: monitor.user_id,
        targetUrl: monitor.target_url,
        verifiedDomain: Boolean(verification),
        monitorId: monitor.id,
        previousScanId: monitor.last_scan_id
      });

      await svc
        .from("monitors")
        .update({
          last_run_at: now,
          next_run_at: addHours(now, monitor.interval_hours),
          last_scan_id: scanId,
          delta_notified_at: null
        })
        .eq("id", monitor.id);

      result.enqueued += 1;
    } catch (e) {
      result.errors.push(`${monitor.id}: ${String(e)}`);
      // Push next run forward so a bad target doesn't block the queue forever.
      await svc
        .from("monitors")
        .update({ next_run_at: addHours(now, monitor.interval_hours) })
        .eq("id", monitor.id);
    }
  }

  return result;
}
