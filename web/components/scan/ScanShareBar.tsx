"use client";

import { useState } from "react";

export default function ScanShareBar({
  scanId,
  target,
  showVerify = true,
  summaryMarkdown,
  note
}: {
  scanId: string | null | undefined;
  target: string;
  showVerify?: boolean;
  summaryMarkdown?: string;
  note?: string;
}) {
  const [copied, setCopied] = useState<string | null>(null);

  async function copy(text: string, which: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(which);
      setTimeout(() => setCopied(null), 1800);
    } catch {
      /* clipboard unavailable */
    }
  }

  if (!scanId) {
    return (
      <div className="scan-share-bar scan-share-muted">
        <div className="scan-share-copy">
          <span className="scan-share-label">{note ? "Share card" : "Not saved"}</span>
          <p>{note ?? "This result is not stored. Connect Supabase to keep a report link."}</p>
        </div>
        {summaryMarkdown && (
          <div className="scan-share-actions">
            <button type="button" className="btn btn-primary btn-sm" onClick={() => copy(summaryMarkdown, "summary")}>
              {copied === "summary" ? "Copied" : "Copy summary"}
            </button>
          </div>
        )}
      </div>
    );
  }

  const reportUrl =
    typeof window !== "undefined"
      ? `${window.location.origin}/scans/${scanId}`
      : `/scans/${scanId}`;
  const verifyUrl = `/verify/${scanId}`;

  return (
    <div className="scan-share-bar">
      <div className="scan-share-copy">
        <span className="scan-share-label">Saved report</span>
        <p className="scan-share-target">{target}</p>
      </div>
      <div className="scan-share-actions">
        <a className="btn btn-primary btn-sm" href={`/scans/${scanId}`}>
          Open full report
        </a>
        {showVerify && (
          <a className="btn btn-ghost btn-sm" href={verifyUrl} target="_blank" rel="noopener noreferrer">
            Trust badge
          </a>
        )}
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => copy(reportUrl, "report")}
        >
          {copied === "report" ? "Copied" : "Copy report link"}
        </button>
        {summaryMarkdown && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => copy(summaryMarkdown, "summary")}>
            {copied === "summary" ? "Copied" : "Copy summary"}
          </button>
        )}
        {showVerify && (
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => copy(`${window.location.origin}${verifyUrl}`, "verify")}
          >
            {copied === "verify" ? "✓ Badge copied" : "Copy badge link"}
          </button>
        )}
      </div>
    </div>
  );
}
