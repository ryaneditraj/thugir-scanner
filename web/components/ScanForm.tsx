"use client";

import { useEffect, useState } from "react";
import ScanResultsPanel from "@/components/scan/ScanResultsPanel";
import type { LockedPreview, ScanAiSummary, ScanFinding, ScanMeta } from "@/components/scan/types";

const SCAN_STEPS = [
  "Loading page like a browser",
  "Fingerprinting the stack",
  "Scanning bundle for exposed secrets",
  "Probing .env / .git / config paths",
  "Testing database access rules",
  "Checking security headers",
  "Verifying evidence before flagging"
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
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const prefill = params.get("scan");
    if (prefill) setUrl(prefill);
  }, []);

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
        <a className="demo-link btn-arrow" href="/demo">
          See a sample report
        </a>
        <span className="scan-note">No https:// needed · free account · ~10s · read-only</span>
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
          />
        </div>
      )}
    </div>
  );
}
