type VerifyStatus = "passed" | "attention";

export type VerifyBadgeData = {
  domain: string;
  scannedAt: string;
  status: VerifyStatus;
  criticalCount: number;
  badgeId?: string;
  isDemo?: boolean;
};

export function VerifyBadgeCard({ domain, scannedAt, status, criticalCount, badgeId, isDemo }: VerifyBadgeData) {
  const dateLabel = scannedAt
    ? new Date(scannedAt).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })
    : null;
  const passed = status === "passed";

  return (
    <div className="verify-wrap">
      {isDemo && (
        <p className="verify-demo-banner">
          <span>● Demo badge — shareable trust seal for judges</span>
        </p>
      )}

      <article className="verify-card" aria-label={`Thugir scan verification for ${domain}`}>
        <header className="verify-head">
          <div className={`verify-seal ${passed ? "pass" : "attention"}`} aria-hidden="true">
            {passed ? (
              <svg viewBox="0 0 64 64" width="64" height="64" fill="none">
                <circle cx="32" cy="32" r="30" stroke="currentColor" strokeWidth="3" />
                <path d="M20 33l8 8 16-18" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            ) : (
              <svg viewBox="0 0 64 64" width="64" height="64" fill="none">
                <circle cx="32" cy="32" r="30" stroke="currentColor" strokeWidth="3" />
                <path d="M32 20v18" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
                <circle cx="32" cy="46" r="3" fill="currentColor" />
              </svg>
            )}
          </div>
          <p className="verify-brand">Thugir verified scan</p>
          <h1 className="verify-domain">{domain}</h1>
        </header>

        <div className="verify-status-row">
          <span className={`verify-status-pill ${passed ? "pass" : "attention"}`}>
            {passed ? "Passed" : "Needs attention"}
          </span>
          <p className="verify-status-copy">
            {passed
              ? "No open critical issues at scan time."
              : `${criticalCount} open critical issue${criticalCount === 1 ? "" : "s"} at scan time.`}
          </p>
        </div>

        <dl className="verify-meta">
          {dateLabel && (
            <>
              <dt>Scanned</dt>
              <dd>{dateLabel}</dd>
            </>
          )}
          <dt>Critical issues</dt>
          <dd>{criticalCount}</dd>
          {badgeId && (
            <>
              <dt>Badge ID</dt>
              <dd className="verify-id">{badgeId}</dd>
            </>
          )}
        </dl>

        <p className="verify-foot">
          Verification reflects the state at scan time only. Full findings stay private to the scan owner.
        </p>
      </article>
    </div>
  );
}
