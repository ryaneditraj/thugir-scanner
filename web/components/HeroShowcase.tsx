// Hero product showcase — three white UI cards rising from the petrol hero band.
// Purely presentational; parent [data-reveal] drives the entrance animation.

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

export default function HeroShowcase({
  freeChecks,
  libraryChecks
}: {
  freeChecks: number;
  libraryChecks: number;
}) {
  return (
    <div className="hs" aria-hidden="true">
      {/* LEFT — live findings feed */}
      <article className="hs-card hs-list">
        <div className="hs-list-head">
          <span className="hs-title">Sample findings</span>
          <span className="hs-live">
            <i className="hs-live-dot" /> Sample
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
          <span className="hs-foot-stat">Illustration, not a live feed</span>
          <span className="hs-foot-link">Evidence required</span>
        </div>
      </article>

      {/* CENTER — resolution / trend (elevated) */}
      <article className="hs-card hs-chart">
        <span className="hs-grab" aria-hidden="true" />
        <div className="hs-chart-top">
          <div className="hs-stat">
            <div className="hs-pct">{freeChecks}</div>
            <div className="hs-stat-label">
              <i className="dot ok" /> Free-tier checks in this repo
            </div>
          </div>
        </div>
        <ul className="hs-metrics">
          <li>
            <span className="hs-m-num ok">{libraryChecks}</span>
            <span className="hs-m-lbl">Enabled patterns</span>
          </li>
          <li>
            <span className="hs-m-num">On</span>
            <span className="hs-m-lbl">Evidence required</span>
          </li>
        </ul>
        <div className="hs-check">
          <span className="tick">✓</span> Deep-scan fields stay off the free response
        </div>
      </article>

      {/* RIGHT — security score */}
      <article className="hs-card hs-score">
        <div className="hs-score-head">
          <span className="hs-title sm">Free-tier checks</span>
        </div>
        <div className="hs-score-sub">Run from this repository</div>
        <div className="hs-chips">
          <span className="on">Headers</span>
          <span className="on">Secrets</span>
          <span className="on">RLS</span>
          <span className="on">.env</span>
          <span className="on">Source maps</span>
        </div>
      </article>
    </div>
  );
}
