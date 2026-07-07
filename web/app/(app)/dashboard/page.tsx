import { redirect } from "next/navigation";
import { getServerSupabase } from "@/lib/supabase/server";
import { resolveUserTier } from "@/lib/entitlements";
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

const TIER_LABEL: Record<string, string> = {
  free: "Free",
  deep: "Deep Scan",
  continuous: "Continuous"
};

export default async function DashboardPage() {
  let user: { id: string; email?: string };
  let scans: ScanRow[] | null = null;

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
    scans = data as ScanRow[] | null;
  }

  const tier = await resolveUserTier(user.id);

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
          {!IS_DEV_MODE && <SignOutButton />}
        </div>
      </header>

      {(tier === "free" || tier === "deep") && <UpgradePanel currentTier={tier} />}

      <DashboardPortal currentTier={tier} />

      {tier === "continuous" && !IS_DEV_MODE && <MonitorsPanel />}

      <section className="dash-history">
        <h2>Recent scans</h2>
        {(!scans || scans.length === 0) && (
          <p className="muted">No scans yet. Run a free scan on the homepage or a Deep Scan above.</p>
        )}
        {scans && scans.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Tier</th>
                  <th>Platform</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td className="mono-cell">{s.target_url}</td>
                    <td>{s.tier}</td>
                    <td>{s.detected_platform ?? "—"}</td>
                    <td>
                      <span className={`status-pill status-${s.status}`}>{s.status}</span>
                    </td>
                    <td>
                      <a className="table-link" href={`/scans/${s.id}`}>
                        View report
                      </a>
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
