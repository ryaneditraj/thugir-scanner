import Link from "next/link";
import AiSummaryPanel from "./AiSummaryPanel";
import FindingCard from "./FindingCard";
import ScanShareBar from "./ScanShareBar";
import SeveritySummary from "./SeveritySummary";
import type { LockedPreview, ScanAiSummary, ScanFinding, ScanMeta } from "./types";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function ScanResultsPanel({
  scanId,
  target,
  tierLabel,
  detectedPlatform,
  pagesCrawled,
  ai,
  meta,
  findings,
  locked,
  showShare = true,
  hideHeader = false
}: {
  scanId?: string | null;
  target: string;
  tierLabel?: string;
  detectedPlatform?: string | null;
  pagesCrawled?: number;
  ai?: ScanAiSummary | null;
  meta?: ScanMeta;
  findings: ScanFinding[];
  locked?: LockedPreview | null;
  showShare?: boolean;
  hideHeader?: boolean;
}) {
  const sorted = [...findings].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );
  const unlocked = sorted.filter((f) => f.unlocked !== false);
  const lockedFindings = sorted.filter((f) => f.unlocked === false);
  const isDeep = tierLabel?.toLowerCase().includes("deep");

  return (
    <section className="scan-results-shell">
      {showShare && <ScanShareBar scanId={scanId} target={target} />}

      {!hideHeader && (
        <p className="result-head">
          {isDeep ? "DEEP SCAN" : "CASE FILE"} · <b>{target}</b>
          {detectedPlatform && (
            <>
              {" "}
              · stack:{" "}
              <Link className="inline-platform" href={`/platforms/${detectedPlatform}`}>
                {detectedPlatform}
              </Link>
            </>
          )}
          {pagesCrawled != null && pagesCrawled > 0 && <> · {pagesCrawled} pages</>}
        </p>
      )}

      <SeveritySummary findings={unlocked} />

      {ai && <AiSummaryPanel ai={ai} />}

      {meta && (meta.aiFindingsAdded ?? 0) > 0 && (
        <p className="scan-meta dim">
          AI added {meta.aiFindingsAdded} finding{meta.aiFindingsAdded === 1 ? "" : "s"}
          {meta.probesRun ? ` · ${meta.probesRun} probes` : ""}
          {meta.pagesCrawled ? ` · ${meta.pagesCrawled} pages` : ""}
        </p>
      )}

      {unlocked.length === 0 && !lockedFindings.length && (
        <p className="dim">No issues confirmed on this target.</p>
      )}

      {unlocked.map((f, i) => (
        <FindingCard key={f.id ?? f.patternSlug ?? f.title} finding={f} index={i} defaultOpen={i === 0 && f.severity === "critical"} />
      ))}

      {lockedFindings.length > 0 && (
        <div className="scan-locked-section">
          <p className="result-head">LOCKED · upgrade to unlock evidence</p>
          {lockedFindings.map((f) => (
            <FindingCard key={f.id ?? f.patternSlug ?? f.title} finding={f} locked />
          ))}
        </div>
      )}

      {locked && locked.checkCount > 0 && (
        <div className="locked-preview" aria-label="The deeper report is locked">
          <span className="locked-ribbon">Sealed · Deep Scan required</span>
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
            <span className="lp-lock" aria-hidden="true">
              🔒
            </span>
            <p className="lp-title">The deeper report is sealed</p>
            <p className="lp-sub">
              A Deep Scan runs {locked.checkCount} more checks
              {locked.categories.length > 0 && (
                <> — {locked.categories.slice(0, 3).join(", ")}</>
              )}{" "}
              — each with captured evidence and a one-paste fix.
            </p>
            <a className="btn btn-primary btn-arrow" href="/dashboard">
              Unlock with a Deep Scan
            </a>
          </div>
        </div>
      )}
    </section>
  );
}
