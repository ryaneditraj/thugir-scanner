"use client";

import { useState, useEffect } from "react";

type Tab = "app" | "code";

interface VisibleFinding {
  patternSlug: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  impactOneline: string;
  maxDamageOneline?: string;
  evidence?: Record<string, unknown>;
  remediation?: { summary: string; steps: string[] };
  fixPrompt?: string;
}
interface DeepResult {
  target: string;
  detectedPlatform: string | null;
  pagesCrawled: string[];
  ai: { summary: string; maxCompanyDamage?: string; attackChain?: string; riskLevel: string; model: string } | null;
  meta?: { totalFindings?: number; aiFindingsAdded?: number; probesRun?: number; pagesCrawled?: number };
  findings: VisibleFinding[];
}

interface CodeFinding {
  ruleId: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  impact: string;
  fix: string;
  file: string;
  line: number;
  snippet: string;
}
interface CodeResult {
  repo: string;
  branch: string;
  filesScanned: number;
  totalFiles: number;
  truncated: boolean;
  findings: CodeFinding[];
  countsBySeverity: Record<string, number>;
}

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
          /* clipboard blocked */
        }
      }}
    >
      {copied ? "✓ Copied" : "Copy fix"}
    </button>
  );
}

const DEEP_STEPS = [
  "Crawling pages and scripts",
  "Running full pattern library",
  "Probing APIs and sensitive paths",
  "AI deep analysis",
  "Packaging evidence and fixes"
];

export default function DashboardPortal({ currentTier }: { currentTier: string }) {
  const canDeepScan = currentTier !== "free";
  const canCodeScan = currentTier !== "free";
  const [tab, setTab] = useState<Tab>("app");

  const [url, setUrl] = useState("");
  const [appBusy, setAppBusy] = useState(false);
  const [appErr, setAppErr] = useState<string | null>(null);
  const [appRes, setAppRes] = useState<DeepResult | null>(null);

  const [appStep, setAppStep] = useState(0);

  const [repo, setRepo] = useState("");
  const [codeBusy, setCodeBusy] = useState(false);
  const [codeErr, setCodeErr] = useState<string | null>(null);
  const [codeRes, setCodeRes] = useState<CodeResult | null>(null);

  useEffect(() => {
    if (!appBusy) return;
    setAppStep(0);
    const id = window.setInterval(() => {
      setAppStep((s) => (s < DEEP_STEPS.length - 1 ? s + 1 : s));
    }, 1200);
    return () => clearInterval(id);
  }, [appBusy]);

  async function runApp(e: React.FormEvent) {
    e.preventDefault();
    setAppBusy(true);
    setAppErr(null);
    setAppRes(null);
    try {
      const res = await fetch("/api/scan/deep-run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      if (!res.ok) setAppErr(data.hint || data.error || "Scan failed");
      else setAppRes(data);
    } catch {
      setAppErr("Network error");
    } finally {
      setAppBusy(false);
    }
  }

  async function runCode(e: React.FormEvent) {
    e.preventDefault();
    setCodeBusy(true);
    setCodeErr(null);
    setCodeRes(null);
    try {
      const res = await fetch("/api/scan/code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo })
      });
      const data = await res.json();
      if (!res.ok) setCodeErr(data.hint || data.error || "Scan failed");
      else setCodeRes(data);
    } catch {
      setCodeErr("Network error");
    } finally {
      setCodeBusy(false);
    }
  }

  return (
    <div className="portal">
      <div className="portal-tabs" role="tablist" aria-label="Scan type">
        <button
          role="tab"
          type="button"
          aria-selected={tab === "app"}
          className={tab === "app" ? "active" : ""}
          onClick={() => setTab("app")}
        >
          App Deep Scan
        </button>
        <button
          role="tab"
          type="button"
          aria-selected={tab === "code"}
          className={tab === "code" ? "active" : ""}
          onClick={() => setTab("code")}
        >
          Code / Repo Scan
        </button>
      </div>

      {tab === "app" && (
        <div className="portal-panel">
          <h2>Deep Scan a live app</h2>
          <p className="portal-sub">
            Crawls a few pages, runs the full pattern library, and returns every confirmed finding
            unlocked — with evidence and fixes.
            {!canDeepScan && (
              <> Requires a <b>Deep</b> or <b>Continuous</b> plan — upgrade above, or use Preview as in admin.</>
            )}
          </p>
          <form className="scan-box" onSubmit={runApp}>
            <div className="scan-field">
              <span className="proto" aria-hidden="true">⌕</span>
              <input
                type="text"
                inputMode="url"
                spellCheck={false}
                autoCapitalize="off"
                placeholder="yourapp.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                disabled={!canDeepScan && !appBusy}
                aria-label="App URL to scan"
              />
            </div>
            <button className="btn btn-primary" type="submit" disabled={appBusy || !canDeepScan}>
              {appBusy ? "Scanning…" : canDeepScan ? "Run Deep Scan" : "Upgrade to scan"}
            </button>
          </form>
          {appBusy && (
            <div className="scan-progress" role="status" aria-live="polite" style={{ marginTop: 14 }}>
              <div className="scan-progress-head">
                <span className="scan-progress-spin" aria-hidden="true" />
                Deep scanning {url || "your app"}…
              </div>
              <ul className="scan-steps">
                {DEEP_STEPS.map((label, i) => (
                  <li key={label} className={i < appStep ? "done" : i === appStep ? "active" : ""}>
                    <span className="sdot" aria-hidden="true" />
                    {label}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {appErr && <p className="notice" style={{ marginTop: 14 }}>{appErr}</p>}

          {appRes && (
            <section style={{ marginTop: 22 }}>
              <p className="result-head">
                DEEP SCAN · <b>{appRes.target}</b>
                {appRes.detectedPlatform && <> · stack: {appRes.detectedPlatform}</>}
                {appRes.pagesCrawled?.length > 0 && <> · {appRes.pagesCrawled.length} pages</>}
              </p>
              {appRes.ai?.summary && (
                <div className={`ai-analysis risk-${appRes.ai.riskLevel}`}>
                  <div className="ai-analysis-head">
                    <span className="ai-chip">◆ Analyst summary</span>
                    <span className={`tag ${appRes.ai.riskLevel === "clean" ? "low" : appRes.ai.riskLevel}`}>
                      {appRes.ai.riskLevel === "clean" ? "no critical risk" : `${appRes.ai.riskLevel} risk`}
                    </span>
                  </div>
                  <p className="ai-summary">{appRes.ai.summary}</p>
                  {appRes.ai.maxCompanyDamage && (
                    <div className="max-company-damage">
                      <div className="max-damage-label">Maximum damage to your company</div>
                      <p>{appRes.ai.maxCompanyDamage}</p>
                    </div>
                  )}
                  {appRes.ai.attackChain && (
                    <div className="attack-chain">
                      <div className="max-damage-label">Likely attack chain</div>
                      <p>{appRes.ai.attackChain}</p>
                    </div>
                  )}
                </div>
              )}
              {appRes.meta && (appRes.meta.aiFindingsAdded ?? 0) > 0 && (
                <p className="scan-meta dim">
                  AI added {appRes.meta.aiFindingsAdded} findings · {appRes.meta.probesRun ?? 0} probes ·{" "}
                  {appRes.meta.pagesCrawled ?? 0} pages
                </p>
              )}
              {appRes.findings.length === 0 && <p className="dim">No issues confirmed on the crawled pages.</p>}
              {appRes.findings.map((f) => (
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
            </section>
          )}
        </div>
      )}

      {tab === "code" && (
        <div className="portal-panel">
          <h2>Scan a code repository</h2>
          <p className="portal-sub">
            Paste a public GitHub repo URL. We read the source and flag hard-coded secrets, injection
            sinks, disabled TLS, unsafe deserialization, and XSS-prone code — with the exact file and line.
          </p>
          <form className="scan-box" onSubmit={runCode}>
            <div className="scan-field">
              <span className="proto" aria-hidden="true">⌕</span>
              <input
                type="text"
                spellCheck={false}
                autoCapitalize="off"
                placeholder="https://github.com/owner/repo"
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
                required
              />
            </div>
            <button className="btn btn-primary" type="submit" disabled={codeBusy || !canCodeScan}>
              {codeBusy ? "Scanning…" : canCodeScan ? "Scan repository" : "Upgrade to scan"}
            </button>
          </form>
          {codeBusy && <p className="dim" style={{ marginTop: 12 }}>Reading the repository and analysing files…</p>}
          {codeErr && <p className="notice" style={{ marginTop: 14 }}>{codeErr}</p>}

          {codeRes && (
            <section style={{ marginTop: 22 }}>
              <p className="result-head">
                CODE SCAN · <b>{codeRes.repo}</b> · branch {codeRes.branch} · {codeRes.filesScanned}/{codeRes.totalFiles} files
                {codeRes.truncated && <> (capped)</>}
              </p>
              {codeRes.findings.length === 0 && (
                <p className="dim">No code-level issues matched on the scanned files.</p>
              )}
              {codeRes.findings.map((f, i) => (
                <div className="finding" key={`${f.ruleId}-${f.file}-${f.line}-${i}`}>
                  <h3>
                    <span className={`tag ${f.severity}`}>{f.severity}</span>
                    <span className="tag low">{f.category}</span>
                    {f.title}
                  </h3>
                  <p className="impact">{f.impact}</p>
                  <div className="code-loc">
                    {f.file}:{f.line}
                  </div>
                  <pre className="code">{f.snippet}</pre>
                  <div className="finding-detail">
                    <div className="fd-block">
                      <div className="fd-label">How to fix</div>
                      <p className="fd-text">{f.fix}</p>
                    </div>
                  </div>
                </div>
              ))}
            </section>
          )}
        </div>
      )}

      {currentTier === "free" && (
        <p className="portal-note">
          You’re on the <b>free</b> plan. Deep and code scans unlock with a Deep or Continuous plan.
          Free scans on the <a href="/" style={{ color: "var(--accent-bright)" }}>homepage</a> still work.
        </p>
      )}
    </div>
  );
}
