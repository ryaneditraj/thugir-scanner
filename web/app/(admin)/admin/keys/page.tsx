import { getServiceSupabase } from "@/lib/supabase/server";
import { IS_DEV_MODE } from "@/lib/devmode";

export const dynamic = "force-dynamic";

type KeyRow = {
  id: string;
  label: string;
  provider: string;
  last4: string;
  status: string;
  rotated_at: string | null;
  created_at: string;
};

export default async function AdminKeysPage() {
  const { data } = IS_DEV_MODE
    ? { data: [] as KeyRow[] }
    : await getServiceSupabase()
        .from("api_keys")
        .select("id, label, provider, last4, status, rotated_at, created_at")
        .order("created_at", { ascending: false });

  return (
    <article>
      <h1 style={{ fontFamily: "var(--display)" }}>API keys</h1>
      <p className="muted">
        Provider keys are encrypted at rest (Vault). Only the last four characters are ever shown.
        Plaintext is never stored or returned by the API.
      </p>
      <table className="table">
        <thead>
          <tr>
            <th>Label</th>
            <th>Provider</th>
            <th>Key</th>
            <th>Status</th>
            <th>Rotated</th>
          </tr>
        </thead>
        <tbody>
          {(data ?? []).map((k) => (
            <tr key={k.id}>
              <td>{k.label}</td>
              <td>{k.provider}</td>
              <td>****{k.last4}</td>
              <td>{k.status}</td>
              <td>{k.rotated_at ? new Date(k.rotated_at).toLocaleDateString() : "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted" style={{ marginTop: 12 }}>
        Add or rotate keys via the admin API (owner role). See the admin runbook.
      </p>
    </article>
  );
}
