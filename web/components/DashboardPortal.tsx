"use client";

import { useEffect, useState } from "react";
import ScanResultsPanel from "@/components/scan/ScanResultsPanel";
import type { ScanAiSummary, ScanFinding, ScanMeta } from "@/components/scan/types";

type Tab = "app" | "code";

interface DeepResult {
  scanId: string | null;
  target: string;
  detectedPlatform: string | null;
  pagesCrawled: string[];
  ai: ScanAiSummary | null;
  meta?: ScanMeta;
  findings: ScanFinding[];
}

interface CodeFinding {
  ruleId: string;
  title: string;
  category: string;
  severity: ScanFinding["severity"];
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
            Crawls multiple pages, runs the full pattern library, and returns every confirmed finding
            with evidence and paste-back fixes.
            {!canDeepScan && (
              <>
                {" "}
                Requires a <b>Deep</b> or <b>Continuous</b> plan — upgrade above.
              </>
            )}
          </p>
          <form className="scan-box" onSubmit={runApp}>
            <div className="scan-field">
              <span className="proto" aria-hidden="true">
                ⌕
              </span>
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
          {appErr && (
            <p className="notice" style={{ marginTop: 14 }}>
              {appErr}
            </p>
          )}

          {appRes && (
            <div style={{ marginTop: 22 }}>
              <ScanResultsPanel
                scanId={appRes.scanId}
                target={appRes.target}
                tierLabel="deep"
                detectedPlatform={appRes.detectedPlatform}
                pagesCrawled={appRes.pagesCrawled?.length ?? appRes.meta?.pagesCrawled}
                ai={appRes.ai}
                meta={appRes.meta}
                findings={appRes.findings}
              />
            </div>
          )}
        </div>
      )}

      {tab === "code" && (
        <div className="portal-panel">
          <h2>Scan a code repository</h2>
          <p className="portal-sub">
            Paste a public GitHub repo URL. We flag hard-coded secrets, injection sinks, and unsafe
            patterns — with the exact file and line.
          </p>
          <form className="scan-box" onSubmit={runCode}>
            <div className="scan-field">
              <span className="proto" aria-hidden="true">
                ⌕
              </span>
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
          {codeBusy && (
            <p className="dim" style={{ marginTop: 12 }}>
              Reading the repository and analysing files…
            </p>
          )}
          {codeErr && (
            <p className="notice" style={{ marginTop: 14 }}>
              {codeErr}
            </p>
          )}

          {codeRes && (
            <section className="scan-results-shell" style={{ marginTop: 22 }}>
              <p className="result-head">
                CODE SCAN · <b>{codeRes.repo}</b> · branch {codeRes.branch} · {codeRes.filesScanned}/
                {codeRes.totalFiles} files
                {codeRes.truncated && <> (capped)</>}
              </p>
              {codeRes.findings.length === 0 && (
                <p className="dim">No code-level issues matched on the scanned files.</p>
              )}
              {codeRes.findings.map((f, i) => (
                <article className="finding-card" key={`${f.ruleId}-${f.file}-${f.line}-${i}`}>
                  <header className="finding-card-head">
                    <div className="finding-card-tags">
                      <span className={`tag ${f.severity}`}>{f.severity}</span>
                      <span className="tag low">{f.category}</span>
                    </div>
                    <h3>{f.title}</h3>
                    <p className="impact">{f.impact}</p>
                    <div className="code-loc">
                      {f.file}:{f.line}
                    </div>
                  </header>
                  <div className="finding-detail">
                    <div className="fd-block">
                      <div className="fd-label">Snippet</div>
                      <pre className="code">{f.snippet}</pre>
                    </div>
                    <div className="fd-block">
                      <div className="fd-label">How to fix</div>
                      <p className="fd-text">{f.fix}</p>
                    </div>
                  </div>
                </article>
              ))}
            </section>
          )}
        </div>
      )}

      {currentTier === "free" && (
        <p className="portal-note">
          You’re on the <b>free</b> plan. Deep and code scans unlock with a Deep or Continuous
          plan. Free scans on the{" "}
          <a href="/" style={{ color: "var(--accent-bright)" }}>
            homepage
          </a>{" "}
          still work.
        </p>
      )}
    </div>
  );
}
