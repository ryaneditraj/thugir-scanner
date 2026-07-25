"use client";

import { useState } from "react";

export default function ScanShareBar({
  scanId,
  target,
  showVerify = true
}: {
  scanId: string | null | undefined;
  target: string;
  showVerify?: boolean;
}) {
  const [copied, setCopied] = useState<string | null>(null);

  if (!scanId) {
    return (
      <div className="scan-share-bar scan-share-muted">
        <p>
          Report saved to your account in production. In local <code>DEV_MODE</code>, scans are not
          persisted — connect Supabase to keep history.
        </p>
      </div>
    );
  }

  const reportUrl =
    typeof window !== "undefined"
      ? `${window.location.origin}/scans/${scanId}`
      : `/scans/${scanId}`;
  const verifyUrl = `/verify/${scanId}`;

  async function copy(text: string, which: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(which);
      setTimeout(() => setCopied(null), 1800);
    } catch {
      /* noop */
    }
  }

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
          {copied === "report" ? "✓ Link copied" : "Copy report link"}
        </button>
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
