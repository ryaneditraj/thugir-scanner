import { getServiceSupabase } from "@/lib/supabase/server";
import { IS_DEV_MODE } from "@/lib/devmode";

export const dynamic = "force-dynamic";

type AuditRow = {
  created_at: string;
  actor_admin_id: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
};

export default async function AdminAuditPage() {
  const { data } = IS_DEV_MODE
    ? { data: [] as AuditRow[] }
    : await getServiceSupabase()
        .from("admin_audit_log")
        .select("created_at, actor_admin_id, action, target_type, target_id, ip")
        .order("created_at", { ascending: false })
        .limit(200);

  return (
    <article>
      <h1 style={{ fontFamily: "var(--display)" }}>Audit log</h1>
      <p className="muted">Append-only. Records who changed what and when.</p>
      <table className="table">
        <thead>
          <tr>
            <th>When</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          {(data ?? []).map((r, i) => (
            <tr key={i}>
              <td>{new Date(r.created_at).toLocaleString()}</td>
              <td>{r.actor_admin_id?.slice(0, 8)}</td>
              <td>{r.action}</td>
              <td>
                {r.target_type}:{r.target_id?.slice(0, 8)}
              </td>
              <td>{r.ip ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}
