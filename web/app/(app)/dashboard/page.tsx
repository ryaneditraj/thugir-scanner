import { redirect } from "next/navigation";
import { getServerSupabase, getServiceSupabase } from "@/lib/supabase/server";
import { resolveUserTier, countDeepCredits } from "@/lib/entitlements";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";
import DashboardPortal from "@/components/DashboardPortal";
import UpgradePanel from "@/components/UpgradePanel";
import SignOutButton from "@/components/SignOutButton";
import MonitorsPanel from "@/components/MonitorsPanel";

export const dynamic = "force-dynamic";

type ScanRow = {
  id: string;
  target_url: string;
  tier: string;
  status: string;
  created_at: string;
  detected_platform: string | null;
};

type ScanSummary = ScanRow & {
  critical: number;
  high: number;
  total: number;
};

const TIER_LABEL: Record<string, string> = {
  free: "Free",
  deep: "Deep Scan",
  continuous: "Continuous"
};

async function enrichScans(scans: ScanRow[]): Promise<ScanSummary[]> {
  if (!scans.length) return [];
  const svc = getServiceSupabase();
  const ids = scans.map((s) => s.id);
  const { data: findings } = await svc
    .from("findings")
    .select("scan_id, severity")
    .in("scan_id", ids);

  const byScan = new Map<string, { critical: number; high: number; total: number }>();
  for (const id of ids) byScan.set(id, { critical: 0, high: 0, total: 0 });
  for (const f of findings ?? []) {
    const agg = byScan.get(f.scan_id);
    if (!agg) continue;
    agg.total += 1;
    if (f.severity === "critical") agg.critical += 1;
    if (f.severity === "high") agg.high += 1;
  }

  return scans.map((s) => ({ ...s, ...(byScan.get(s.id) ?? { critical: 0, high: 0, total: 0 }) }));
}

export default async function DashboardPage() {
  let user: { id: string; email?: string };
  let scans: ScanSummary[] = [];

  if (IS_DEV_MODE) {
    user = DEV_USER;
  } else {
    const supabase = getServerSupabase();
    const {
      data: { user: authed }
    } = await supabase.auth.getUser();
    if (!authed) redirect("/login");
    user = authed;
    const { data } = await supabase
      .from("scans")
      .select("id, target_url, tier, status, created_at, detected_platform")
      .order("created_at", { ascending: false })
      .limit(25);
    scans = await enrichScans((data as ScanRow[]) ?? []);
  }

  const tier = await resolveUserTier(user.id);
  const deepCredits = await countDeepCredits(user.id);

  return (
    <article className="dash">
      {IS_DEV_MODE && (
        <p className="notice" style={{ marginBottom: 18 }}>
          DEV_MODE is on — auth is bypassed and scans are not persisted. Set <code>DEV_TIER</code>{" "}
          to test tier-gated views.
        </p>
      )}

      <header className="dash-hero">
        <div>
          <p className="dash-eyebrow">Account</p>
          <h1>Scanner portal</h1>
          <p className="kv">
            Signed in as <b>{user.email}</b>
          </p>
        </div>
        <div className="dash-plan">
          <span className="dash-plan-label">Current plan</span>
          <span className={`dash-plan-badge tier-${tier}`}>{TIER_LABEL[tier] ?? tier}</span>
          {deepCredits > 0 && (
            <span className="dash-credit-pill">
              {deepCredits} Deep credit{deepCredits === 1 ? "" : "s"}
            </span>
          )}
          {!IS_DEV_MODE && <SignOutButton />}
        </div>
      </header>

      {(tier === "free" || tier === "deep") && (
        <UpgradePanel currentTier={tier} deepCredits={deepCredits} />
      )}

      <DashboardPortal currentTier={tier} />

      {tier === "continuous" && !IS_DEV_MODE && <MonitorsPanel />}

      <section className="dash-history">
        <h2>Recent scans</h2>
        {scans.length === 0 && (
          <p className="muted">
            No scans yet. Run a free scan on the homepage or a Deep Scan above — reports are saved
            here automatically.
          </p>
        )}
        {scans.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Findings</th>
                  <th>Tier</th>
                  <th>Platform</th>
                  <th>When</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td className="mono-cell">{s.target_url}</td>
                    <td>
                      {s.total === 0 ? (
                        <span className="dim">—</span>
                      ) : (
                        <span className="scan-count-cell">
                          {s.critical > 0 && (
                            <span className="sev-pill critical compact">
                              <b>{s.critical}</b> crit
                            </span>
                          )}
                          {s.high > 0 && (
                            <span className="sev-pill high compact">
                              <b>{s.high}</b> high
                            </span>
                          )}
                          {s.critical === 0 && s.high === 0 && (
                            <span className="dim">{s.total} total</span>
                          )}
                        </span>
                      )}
                    </td>
                    <td>{s.tier}</td>
                    <td>{s.detected_platform ?? "—"}</td>
                    <td className="dim">{new Date(s.created_at).toLocaleDateString()}</td>
                    <td>
                      <span className={`status-pill status-${s.status}`}>{s.status}</span>
                    </td>
                    <td className="scan-row-actions">
                      <a className="table-link" href={`/scans/${s.id}`}>
                        Report
                      </a>
                      {s.status === "done" && (
                        <a className="table-link" href={`/verify/${s.id}`}>
                          Badge
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </article>
  );
}
