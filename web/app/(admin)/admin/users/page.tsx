import { getServiceSupabase } from "@/lib/supabase/server";
import { IS_DEV_MODE } from "@/lib/devmode";

export const dynamic = "force-dynamic";

type ProfileRow = { id: string; email: string | null; default_tier: string; created_at: string };
type EntRow = { user_id: string; kind: string; status: string };

export default async function AdminUsersPage() {
  let profiles: ProfileRow[] | null = [];
  let ents: EntRow[] | null = [];
  if (!IS_DEV_MODE) {
    const svc = getServiceSupabase();
    ({ data: profiles } = await svc
      .from("profiles")
      .select("id, email, default_tier, created_at")
      .order("created_at", { ascending: false })
      .limit(100));
    ({ data: ents } = await svc
      .from("entitlements")
      .select("user_id, kind, status")
      .eq("status", "active"));
  }

  const byUser = new Map<string, string[]>();
  for (const e of ents ?? []) {
    const list = byUser.get(e.user_id) ?? [];
    list.push(e.kind);
    byUser.set(e.user_id, list);
  }

  return (
    <article>
      <h1 style={{ fontFamily: "var(--display)" }}>Users</h1>
      <p className="muted">View users, plans, and active entitlements. Overrides via admin API.</p>
      <table className="table">
        <thead>
          <tr>
            <th>Email</th>
            <th>Joined</th>
            <th>Active entitlements</th>
          </tr>
        </thead>
        <tbody>
          {(profiles ?? []).map((p) => (
            <tr key={p.id}>
              <td>{p.email ?? p.id.slice(0, 8)}</td>
              <td>{new Date(p.created_at).toLocaleDateString()}</td>
              <td>{(byUser.get(p.id) ?? []).join(", ") || "free"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}
