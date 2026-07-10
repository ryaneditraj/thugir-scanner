import { getServiceSupabase } from "@/lib/supabase/server";
import { IS_DEV_MODE } from "@/lib/devmode";
import { STATIC_PATTERNS } from "@/lib/patterns";
import { agentAvailability } from "@/lib/agent";

export const dynamic = "force-dynamic";

function envStatus(name: string): "ok" | "warn" | "bad" {
  const v = (process.env[name] || "").trim();
  if (!v) return "bad";
  if (/demo|placeholder|your_/i.test(v)) return "warn";
  return "ok";
}

export default async function AdminOverview() {
  let scanCount: number | null = 0;
  let patternCount: number | null = STATIC_PATTERNS.length;
  let openCrit: number | null = 0;
  let userCount: number | null = 0;
  let supabaseOk = false;

  if (!IS_DEV_MODE) {
    try {
      const svc = getServiceSupabase();
      const [s, p, c, u] = await Promise.all([
        svc.from("scans").select("id", { count: "exact", head: true }),
        svc.from("patterns").select("id", { count: "exact", head: true }).eq("enabled", true),
        svc
          .from("findings")
          .select("id", { count: "exact", head: true })
          .eq("severity", "critical")
          .eq("status", "open"),
        svc.from("profiles").select("id", { count: "exact", head: true })
      ]);
      scanCount = s.count;
      patternCount = p.count ?? STATIC_PATTERNS.length;
      openCrit = c.count;
      userCount = u.count;
      supabaseOk = !s.error;
    } catch {
      supabaseOk = false;
    }
  } else {
    supabaseOk = false;
  }

  const agent = agentAvailability();

  const health: [string, "ok" | "warn" | "bad", string][] = [
    [
      "Supabase",
      IS_DEV_MODE ? "warn" : supabaseOk ? "ok" : "bad",
      IS_DEV_MODE ? "DEV_MODE (not connected)" : supabaseOk ? "Connected" : "Check env / service role"
    ],
    [
      "Razorpay",
      envStatus("RAZORPAY_KEY_ID") === "ok" && envStatus("RAZORPAY_KEY_SECRET") === "ok"
        ? envStatus("RAZORPAY_WEBHOOK_SECRET") === "ok"
          ? "ok"
          : "warn"
        : "bad",
      envStatus("RAZORPAY_KEY_ID") === "ok" ? "Keys present" : "Keys missing"
    ],
    [
      "Worker",
      envStatus("WORKER_URL") === "ok" ? "ok" : "warn",
      process.env.WORKER_URL ? "Configured" : "WORKER_URL unset (inline deep-run still works)"
    ],
    [
      "AI analyst",
      envStatus("HACK_CLUB_AI_API_KEY") === "ok" || envStatus("OPENROUTER_API_KEY") === "ok" ? "ok" : "warn",
      process.env.HACK_CLUB_AI_API_KEY
        ? "Hack Club AI ready"
        : process.env.OPENROUTER_API_KEY
          ? "OpenRouter ready"
          : "Optional — set HACK_CLUB_AI_API_KEY or save a key in Settings"
    ],
    [
      "Agent engine",
      agent.available ? "ok" : "warn",
      agent.available ? `Python ready (${agent.python})` : agent.reason || "Optional — local/worker only"
    ]
  ];

  return (
    <article>
      <h1 className="admin-h1">Overview</h1>
      <p className="muted" style={{ marginBottom: 18 }}>
        Operator console for scans, patterns, billing entitlements, and platform health.
      </p>
      <div className="grid">
        <div className="card">
          <b className="stat">{scanCount ?? 0}</b>
          <p className="kv">total scans</p>
        </div>
        <div className="card">
          <b className="stat">{patternCount ?? 0}</b>
          <p className="kv">active patterns</p>
        </div>
        <div className="card">
          <b className="stat">{openCrit ?? 0}</b>
          <p className="kv">open critical findings</p>
        </div>
        <div className="card">
          <b className="stat">{userCount ?? 0}</b>
          <p className="kv">profiles</p>
        </div>
      </div>

      <h2 style={{ fontFamily: "var(--display)", marginTop: 28, fontSize: 20 }}>Integrations</h2>
      <div className="health-grid">
        {health.map(([name, status, detail]) => (
          <div className="health-card" key={name}>
            <b>{name}</b>
            <span className={status === "ok" ? "health-ok" : status === "warn" ? "health-warn" : "health-bad"}>
              {detail}
            </span>
          </div>
        ))}
      </div>
    </article>
  );
}
