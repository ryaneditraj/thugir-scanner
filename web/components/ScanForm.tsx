"use client";

import { useEffect, useState } from "react";
import ScanResultsPanel from "@/components/scan/ScanResultsPanel";
import type { LockedPreview, ScanAiSummary, ScanFinding, ScanMeta } from "@/components/scan/types";
import { reportMarkdown } from "@/lib/share/report-markdown";

const PASS_CHECKS = [
  "Fetch the page and a capped set of same-origin scripts",
  "Fingerprint the stack from what was fetched",
  "Match secret patterns only when the text hits",
  "Probe a fixed set of paths such as .env and .git",
  "Read security headers on the response",
  "Drop any hit that did not capture evidence"
];

interface FreeResult {
  scanId: string | null;
  tier?: string;
  target: string;
  detectedPlatform: string | null;
  ai: ScanAiSummary | null;
  meta?: ScanMeta;
  findings: ScanFinding[];
  locked: LockedPreview | null;
}

export default function ScanForm() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FreeResult | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const prefill = params.get("scan");
    if (prefill) setUrl(prefill);
  }, []);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await fetch("/api/scan/free", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, attest: true })
      });
      if (res.status === 401) {
        window.location.assign(`/login?next=${encodeURIComponent(`/?scan=${url}`)}`);
        return;
      }
      const data = await res.json();
      if (!res.ok) setError(data.error ?? "Scan failed");
      else setResult(data);
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
          <span className="proto" aria-hidden="true">
            ⌕
          </span>
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
            Running the free-tier pass on {url || "that URL"}
          </div>
          <p className="scan-progress-note">
            One request. These are the checks in that pass, not a live status feed.
          </p>
          <ul className="scan-steps">
            {PASS_CHECKS.map((label) => (
              <li key={label}>
                <span className="sdot" aria-hidden="true" />
                {label}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="scan-actions">
        <a className="demo-link" href="/demo">
          Open the labeled sample
        </a>
        <span className="scan-note">Read-only · only scan a host you are allowed to test</span>
      </div>
      <p className="consent">
        By running a scan you confirm you’re authorized to test this site. Scans are logged to your
        account.
      </p>

      {error && (
        <p className="notice" style={{ marginTop: 16 }}>
          {error}
        </p>
      )}

      {result && (
        <div style={{ marginTop: 28 }}>
          <ScanResultsPanel
            scanId={result.scanId}
            target={result.target}
            tierLabel={result.tier && result.tier !== "free" ? "deep" : "free"}
            detectedPlatform={result.detectedPlatform}
            ai={result.ai}
            meta={result.meta}
            findings={result.findings}
            locked={result.locked}
            shareNote="Local runs are not stored. Copy the summary if you want to keep this result."
            summaryMarkdown={reportMarkdown({
              synthetic: false,
              target: result.target,
              detectedPlatform: result.detectedPlatform,
              findings: result.findings
            })}
          />
        </div>
      )}
    </div>
  );
}
