// Hero product showcase — three white UI cards rising from the petrol hero band.
// Purely presentational; parent [data-reveal] drives the entrance animation.

const BARS = [38, 52, 44, 68, 48, 82, 56, 74, 62, 88, 70, 92];

const FINDINGS = [
  {
    sev: "critical" as const,
    title: ".env reachable",
    path: "my-app.com/.env",
    icon: "!"
  },
  {
    sev: "high" as const,
    title: "Supabase RLS off",
    path: "profiles table readable",
    icon: "⚠"
  },
  {
    sev: "medium" as const,
    title: "Missing CSP header",
    path: "clickjacking risk",
    icon: "◆"
  }
];

const SEV_STYLE: Record<string, { bg: string; color: string }> = {
  critical: { bg: "#f4796a", color: "#fff" },
  high: { bg: "#eaa85f", color: "#1a1208" },
  medium: { bg: "#6cbbe6", color: "#0a2028" }
};

export default function HeroShowcase() {
  return (
    <div className="hs" aria-hidden="true">
      {/* LEFT — live findings feed */}
      <article className="hs-card hs-list">
        <div className="hs-list-head">
          <span className="hs-title">Recent findings</span>
          <span className="hs-live">
            <i className="hs-live-dot" /> Live
          </span>
        </div>
        <ul className="hs-feed">
          {FINDINGS.map((f) => (
            <li className="hs-find" key={f.title}>
              <span
                className="hs-avatar"
                style={{ background: SEV_STYLE[f.sev].bg, color: SEV_STYLE[f.sev].color }}
              >
                {f.icon}
              </span>
              <div className="hs-find-main">
                <b>{f.title}</b>
                <span>{f.path}</span>
              </div>
              <span className={`hs-find-sev ${f.sev}`}>{f.sev}</span>
            </li>
          ))}
        </ul>
        <div className="hs-list-foot">
          <span className="hs-foot-stat">
            <b>3</b> confirmed today
          </span>
          <span className="hs-foot-link">View report →</span>
        </div>
      </article>

      {/* CENTER — resolution / trend (elevated) */}
      <article className="hs-card hs-chart">
        <span className="hs-grab" aria-hidden="true" />
        <div className="hs-chart-top">
          <div className="hs-stat">
            <div className="hs-pct">94%</div>
            <div className="hs-stat-label">
              <i className="dot ok" /> Issues resolved
            </div>
          </div>
          <div className="hs-ring-mini" aria-hidden="true">
            <svg viewBox="0 0 36 36" width="36" height="36">
              <circle cx="18" cy="18" r="14" className="rm-track" />
              <circle cx="18" cy="18" r="14" className="rm-fill" />
            </svg>
          </div>
        </div>
        <ul className="hs-metrics">
          <li>
            <span className="hs-m-num warn">3</span>
            <span className="hs-m-lbl">Critical open</span>
          </li>
          <li>
            <span className="hs-m-num ok">12</span>
            <span className="hs-m-lbl">Fixed this week</span>
          </li>
        </ul>
        <div className="hs-bars" aria-hidden="true">
          {BARS.map((h, i) => (
            <span key={i} style={{ height: `${h}%` }} className={i >= 9 ? "peak" : i >= 5 ? "mid" : ""} />
          ))}
        </div>
        <div className="hs-axis">
          <span>Nov</span>
          <span>May</span>
        </div>
        <div className="hs-check">
          <span className="tick">✓</span> Re-scan passed · no new criticals
        </div>
      </article>

      {/* RIGHT — security score */}
      <article className="hs-card hs-score">
        <div className="hs-score-head">
          <span className="hs-title sm">Security score</span>
          <span className="hs-delta">+8 pts</span>
        </div>
        <div className="hs-score-sub">Across 25 scanned pages</div>
        <div className="hs-gauge">
          <svg viewBox="0 0 120 120" width="112" height="112" aria-hidden="true">
            <defs>
              <linearGradient id="hs-gauge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#57b4cd" />
                <stop offset="100%" stopColor="#2f93b0" />
              </linearGradient>
            </defs>
            <circle cx="60" cy="60" r="50" className="g-track" />
            <circle cx="60" cy="60" r="50" className="g-fill" stroke="url(#hs-gauge-grad)" />
          </svg>
          <div className="hs-gauge-center">
            <span className="hs-g-num">82</span>
            <span className="hs-g-lbl">/ 100</span>
          </div>
        </div>
        <div className="hs-chips">
          <span className="on">Headers</span>
          <span className="warn">Secrets</span>
          <span className="on">RLS</span>
          <span>Auth</span>
          <span className="on">TLS</span>
        </div>
      </article>
    </div>
  );
}
