import type { ScanFinding } from "./types";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

type Severity = ScanFinding["severity"];

export default function SeveritySummary({ findings }: { findings: ScanFinding[] }) {
  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  if (findings.length === 0) {
    return (
      <div className="sev-summary" aria-label="Findings by severity">
        <span className="sev-pill clean">
          <b>0</b> confirmed issues
        </span>
      </div>
    );
  }

  return (
    <div className="sev-summary" aria-label="Findings by severity">
      {ORDER.map((k) => (
        <span key={k} className={`sev-pill ${k}${counts[k] ? "" : " zero"}`}>
          <b>{counts[k] ?? 0}</b> {k}
        </span>
      ))}
    </div>
  );
}
