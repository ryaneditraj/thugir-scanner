import { getServiceSupabase } from "@/lib/supabase/server";
import { IS_DEV_MODE } from "@/lib/devmode";
import KillButton from "@/components/KillButton";

export const dynamic = "force-dynamic";

type ScanRow = {
  id: string;
  target_url: string;
  tier: string;
  status: string;
  user_id: string | null;
  created_at: string;
};

export default async function AdminScansPage() {
  const { data } = IS_DEV_MODE
    ? { data: [] as ScanRow[] }
    : await getServiceSupabase()
        .from("scans")
        .select("id, target_url, tier, status, user_id, created_at")
        .order("created_at", { ascending: false })
        .limit(100);

  return (
    <article>
      <h1 style={{ fontFamily: "var(--display)" }}>Scan oversight</h1>
      <p className="muted">View in-flight and past scans; kill stuck or abusive jobs.</p>
      <table className="table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Tier</th>
            <th>Status</th>
            <th>User</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {(data ?? []).map((s) => (
            <tr key={s.id}>
              <td>{s.target_url}</td>
              <td>{s.tier}</td>
              <td>{s.status}</td>
              <td>{s.user_id?.slice(0, 8)}</td>
              <td>
                {(s.status === "queued" || s.status === "running") && <KillButton scanId={s.id} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}
