import { formatEvidence } from "@/lib/findings/format-evidence";
import CopyFixButton from "./CopyFixButton";
import type { ScanFinding } from "./types";

export default function FindingCard({
  finding,
  index,
  locked = false,
  defaultOpen = false
}: {
  finding: ScanFinding;
  index?: number;
  locked?: boolean;
  defaultOpen?: boolean;
}) {
  const key = finding.id ?? finding.patternSlug ?? finding.title;
  const { transcript, rows } = formatEvidence(finding.evidence);
  const hasDetail =
    !locked &&
    (transcript || rows.length > 0 || finding.remediation || finding.fixPrompt || finding.maxDamageOneline);

  if (locked) {
    return (
      <div className="finding locked" key={key}>
        <h3>
          <span className={`tag ${finding.severity}`}>{finding.severity}</span>
          {finding.title}
        </h3>
        <p className="impact">{finding.impactOneline}</p>
        <div className="lock-row">
          <span aria-hidden="true">🔒</span>
          <span>
            Unlock full evidence + fix with a {finding.tierRequired ?? "deep"} scan.
          </span>
        </div>
      </div>
    );
  }

  return (
    <article className={`finding-card${defaultOpen ? " finding-card-open" : ""}`} key={key}>
      <header className="finding-card-head">
        <div className="finding-card-tags">
          {index != null && (
            <span className="finding-card-idx">
              {String(index + 1).padStart(2, "0")}
            </span>
          )}
          <span className={`tag ${finding.severity}`}>{finding.severity}</span>
          <span className="tag verified">verified</span>
          {finding.category && <span className="tag low">{finding.category}</span>}
          {finding.status && finding.status !== "open" && (
            <span className="tag low">{finding.status}</span>
          )}
        </div>
        <h3>{finding.title}</h3>
        <p className="impact">{finding.impactOneline}</p>
        {finding.maxDamageOneline && (
          <div className="max-damage">
            <span className="max-damage-label">Worst case for your company</span>
            <p>{finding.maxDamageOneline}</p>
          </div>
        )}
      </header>

      {hasDetail && (
        <details className="finding-card-body" open={defaultOpen}>
          <summary>Evidence &amp; fix</summary>
          <div className="finding-detail">
            {transcript && (
              <div className="fd-block">
                <div className="fd-label">Evidence captured</div>
                <pre className="fd-evidence app-evidence">{transcript}</pre>
              </div>
            )}
            {rows.length > 0 && (
              <div className="fd-block">
                <div className="fd-label">Details</div>
                <dl className="evidence-dl">
                  {rows.map((r) => (
                    <div className="evidence-row" key={r.label}>
                      <dt>{r.label}</dt>
                      <dd>{r.value}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            )}
            {finding.remediation && (
              <div className="fd-block">
                <div className="fd-label">How to fix</div>
                <p className="fd-text">{finding.remediation.summary}</p>
                {finding.remediation.steps?.length > 0 && (
                  <ol className="fd-steps">
                    {finding.remediation.steps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                )}
              </div>
            )}
            {finding.fixPrompt && (
              <div className="fd-block">
                <div className="fd-label fixprompt-head">
                  <span>Paste into your editor / AI assistant</span>
                  <CopyFixButton text={finding.fixPrompt} />
                </div>
                <pre className="code">{finding.fixPrompt}</pre>
              </div>
            )}
          </div>
        </details>
      )}
    </article>
  );
}
