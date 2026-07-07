"use client";

import { useEffect, useState } from "react";

// The real check families the free scan runs server-side. We surface them as live progress so
// the scan feels as thorough as it is — every label maps to an actual check the engine performs.
const SCAN_STEPS = [
  "Loading page like a browser",
  "Fingerprinting the stack",
  "Scanning bundle for exposed secrets",
  "Probing .env / .git / config paths",
  "Testing database access rules",
  "Checking security headers",
  "Verifying evidence before flagging"
];

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

interface VisibleFinding {
  patternSlug: string;
  category: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  tierRequired: string;
  impactOneline: string;
  maxDamageOneline?: string;
  unlocked: boolean;
  evidence?: Record<string, unknown>;
  remediation?: { summary: string; steps: string[] };
  fixPrompt?: string;
}

interface AiAnalysis {
  summary: string;
  maxCompanyDamage?: string;
  attackChain?: string;
  riskLevel: "critical" | "high" | "medium" | "low" | "clean";
  model: string;
}

interface ScanMeta {
  totalFindings?: number;
  aiFindingsAdded?: number;
  probesRun?: number;
}

interface FreeResult {
  scanId: string | null;
  tier?: string;
  target: string;
  detectedPlatform: string | null;
  ai: AiAnalysis | null;
  meta?: ScanMeta;
  findings: VisibleFinding[];
  // Honest summary of what a Deep Scan adds — a COUNT of additional checks, never fabricated
  // "findings". Rendered as a blurred, locked paywall preview. Null for deep/continuous users.
  locked: { checkCount: number; categories: string[] } | null;
}

// Turn the evidence object into readable `key: value` lines for the Evidence block.
function evidenceLines(ev?: Record<string, unknown>): string {
  if (!ev) return "";
  return Object.entries(ev)
    .map(([k, v]) => `${k}: ${v && typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join("\n");
}

function CopyFix({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={`copy-fix${copied ? " copied" : ""}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1800);
        } catch {
          /* clipboard blocked — no-op */
        }
      }}
    >
      {copied ? "✓ Copied" : "Copy fix prompt"}
    </button>
  );
}

export default function ScanForm() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FreeResult | null>(null);
  const [step, setStep] = useState(0);

  // Advance the live progress steps while the request is in flight. Holds on the final step
  // until the response lands, so we never claim "done" before we have the report.
  useEffect(() => {
    if (!loading) return;
    setStep(0);
    const id = window.setInterval(() => {
      setStep((s) => (s < SCAN_STEPS.length - 1 ? s + 1 : s));
    }, 900);
    return () => clearInterval(id);
  }, [loading]);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await fetch("/api/scan/free", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Submitting the form is the authorization attestation (disclosed in the consent line).
        body: JSON.stringify({ url, attest: true })
      });
      if (res.status === 401) {
        // Account is required to run a scan — carry the intended target through sign-in.
        window.location.assign(`/login?next=${encodeURIComponent(`/?scan=${url}`)}`);
        return;
      }
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Scan failed");
      } else {
        setResult(data);
      }
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div id="scan">
      <form className="scan-box" onSubmit={run}>
        <div className="scan-field">
          <span className="proto" aria-hidden="true">⌕</span>
          <input
            type="text"
            inputMode="url"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            required
            placeholder="yourapp.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            aria-label="Your app's domain or URL"
          />
        </div>
        <button className="btn btn-primary" type="submit" disabled={loading}>
          {loading ? "Scanning…" : "Run a free scan"}
        </button>
      </form>
      {loading && (
        <div className="scan-progress" role="status" aria-live="polite">
          <div className="scan-progress-head">
            <span className="scan-progress-spin" aria-hidden="true" />
            Scanning {url || "your app"}…
          </div>
          <ul className="scan-steps">
            {SCAN_STEPS.map((label, i) => (
              <li key={label} className={i < step ? "done" : i === step ? "active" : ""}>
                <span className="sdot" aria-hidden="true" />
                {label}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="scan-actions">
        <a className="demo-link btn-arrow" href="/demo">See a sample report</a>
        <span className="scan-note">No https:// needed · free account · ~10s · read-only</span>
      </div>
      <p className="consent">
        By running a scan you confirm you’re authorized to test this site. Scans are logged to your account.
      </p>

      {error && (
        <p className="notice" style={{ marginTop: 16 }}>
          {error}
        </p>
      )}

      {result && (() => {
        const findings = [...result.findings].sort(
          (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
        );
        const counts = findings.reduce<Record<string, number>>((acc, f) => {
          acc[f.severity] = (acc[f.severity] ?? 0) + 1;
          return acc;
        }, {});
        const sevKeys: Array<"critical" | "high" | "medium" | "low"> = ["critical", "high", "medium", "low"];
        return (
        <section style={{ marginTop: 28 }}>
          <p className="result-head">
            {result.tier && result.tier !== "free" ? "DEEP SCAN" : "CASE FILE"} · <b>{result.target}</b>
            {result.detectedPlatform && <> · stack: {result.detectedPlatform}</>}
            {result.tier && result.tier !== "free" && <> · all findings unlocked</>}
          </p>

          <div className="sev-summary" aria-label="Findings by severity">
            {findings.length === 0 ? (
              <span className="sev-pill clean"><b>0</b> confirmed issues</span>
            ) : (
              sevKeys.map((k) => (
                <span key={k} className={`sev-pill ${k}${counts[k] ? "" : " zero"}`}>
                  <b>{counts[k] ?? 0}</b> {k}
                </span>
              ))
            )}
          </div>

          {result.ai && result.ai.summary && (
            <div className={`ai-analysis risk-${result.ai.riskLevel}`}>
              <div className="ai-analysis-head">
                <span className="ai-chip">◆ Analyst summary</span>
                <span className={`tag ${result.ai.riskLevel === "clean" ? "low" : result.ai.riskLevel}`}>
                  {result.ai.riskLevel === "clean" ? "no critical risk" : `${result.ai.riskLevel} risk`}
                </span>
              </div>
              <p className="ai-summary">{result.ai.summary}</p>
              {result.ai.maxCompanyDamage && (
                <div className="max-company-damage">
                  <div className="max-damage-label">Maximum damage to your company</div>
                  <p>{result.ai.maxCompanyDamage}</p>
                </div>
              )}
              {result.ai.attackChain && (
                <div className="attack-chain">
                  <div className="max-damage-label">Likely attack chain</div>
                  <p>{result.ai.attackChain}</p>
                </div>
              )}
            </div>
          )}

          {result.meta && (result.meta.aiFindingsAdded ?? 0) > 0 && (
            <p className="scan-meta dim">
              AI deep analysis added {result.meta.aiFindingsAdded} finding
              {result.meta.aiFindingsAdded === 1 ? "" : "s"}
              {result.meta.probesRun ? ` · ${result.meta.probesRun} HTTP probes` : ""}
            </p>
          )}

          {findings.length === 0 && (
            <p className="dim">No free-tier issues confirmed on this target. A Deep Scan probes further — see below.</p>
          )}
          {findings.map((f) => (
            <div className="finding" key={f.patternSlug}>
              <h3>
                <span className={`tag ${f.severity}`}>{f.severity}</span>
                <span className="tag verified">verified</span>
                {f.title}
              </h3>
              <p className="impact">{f.impactOneline}</p>
              {f.maxDamageOneline && (
                <div className="max-damage">
                  <span className="max-damage-label">Worst case for your company</span>
                  <p>{f.maxDamageOneline}</p>
                </div>
              )}
              {(f.evidence || f.remediation) && (
                <details>
                  <summary>Evidence &amp; fix</summary>
                  <div className="finding-detail">
                    {f.evidence && (
                      <div className="fd-block">
                        <div className="fd-label">Evidence</div>
                        <pre className="code">{evidenceLines(f.evidence)}</pre>
                      </div>
                    )}
                    {f.remediation && (
                      <div className="fd-block">
                        <div className="fd-label">How to fix</div>
                        <p className="fd-text">{f.remediation.summary}</p>
                        {f.remediation.steps.length > 0 && (
                          <ol className="fd-steps">
                            {f.remediation.steps.map((s, i) => (
                              <li key={i}>{s}</li>
                            ))}
                          </ol>
                        )}
                      </div>
                    )}
                    {f.fixPrompt && (
                      <div className="fd-block">
                        <div className="fd-label fixprompt-head">
                          <span>Paste into your editor / AI assistant</span>
                          <CopyFix text={f.fixPrompt} />
                        </div>
                        <pre className="code">{f.fixPrompt}</pre>
                      </div>
                    )}
                  </div>
                </details>
              )}
            </div>
          ))}

          {result.locked && result.locked.checkCount > 0 && (
            <div className="locked-preview" aria-label="The deeper report is locked">
              <div className="locked-cards" aria-hidden="true">
                {[0, 1, 2].map((i) => (
                  <div className="locked-card" key={i}>
                    <span className="lp-bar lp-bar-title" />
                    <span className="lp-bar" />
                    <span className="lp-bar short" />
                  </div>
                ))}
              </div>
              <div className="locked-overlay">
                <span className="lp-lock" aria-hidden="true">🔒</span>
                <p className="lp-title">The deeper report is sealed</p>
                <p className="lp-sub">
                  A Deep Scan runs {result.locked.checkCount} more checks
                  {result.locked.categories.length > 0 && (
                    <> — {result.locked.categories.slice(0, 3).join(", ")}</>
                  )}{" "}
                  — each with captured evidence and a one-paste fix.
                </p>
                <a className="btn btn-primary btn-arrow" href="/dashboard">Unlock with a Deep Scan</a>
              </div>
            </div>
          )}
        </section>
        );
      })()}
    </div>
  );
}
