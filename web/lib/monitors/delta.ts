export type FindingRow = {
  category: string;
  title: string;
  severity: string;
  impact_oneline: string;
};

function fingerprint(f: FindingRow): string {
  return `${f.category}::${f.title}::${f.severity}`;
}

export type ScanDelta = {
  newFindings: FindingRow[];
  resolvedFindings: FindingRow[];
  unchangedCount: number;
};

export function computeScanDelta(previous: FindingRow[], current: FindingRow[]): ScanDelta {
  const prevMap = new Map(previous.map((f) => [fingerprint(f), f]));
  const currMap = new Map(current.map((f) => [fingerprint(f), f]));

  const newFindings: FindingRow[] = [];
  for (const [key, f] of currMap) {
    if (!prevMap.has(key)) newFindings.push(f);
  }

  const resolvedFindings: FindingRow[] = [];
  for (const [key, f] of prevMap) {
    if (!currMap.has(key)) resolvedFindings.push(f);
  }

  let unchangedCount = 0;
  for (const key of currMap.keys()) {
    if (prevMap.has(key)) unchangedCount += 1;
  }

  return { newFindings, resolvedFindings, unchangedCount };
}

export function formatDeltaText(
  targetUrl: string,
  delta: ScanDelta,
  scanUrl: string
): { subject: string; text: string; html: string } {
  const hasChanges = delta.newFindings.length > 0 || delta.resolvedFindings.length > 0;
  const subject = hasChanges
    ? `[Thugir] ${delta.newFindings.length} new issue(s) on ${targetUrl}`
    : `[Thugir] Monitor scan complete — no new issues on ${targetUrl}`;

  const lines: string[] = [
    `Continuous Protection scan for ${targetUrl}`,
    "",
    `View full report: ${scanUrl}`,
    ""
  ];

  if (delta.newFindings.length) {
    lines.push(`New findings (${delta.newFindings.length}):`);
    for (const f of delta.newFindings.slice(0, 12)) {
      lines.push(`  • [${f.severity}] ${f.title} — ${f.impact_oneline}`);
    }
    if (delta.newFindings.length > 12) {
      lines.push(`  … and ${delta.newFindings.length - 12} more`);
    }
    lines.push("");
  }

  if (delta.resolvedFindings.length) {
    lines.push(`Resolved since last scan (${delta.resolvedFindings.length}):`);
    for (const f of delta.resolvedFindings.slice(0, 8)) {
      lines.push(`  • [${f.severity}] ${f.title}`);
    }
    lines.push("");
  }

  if (!hasChanges) {
    lines.push(`No new or resolved findings. ${delta.unchangedCount} issue(s) unchanged.`);
  }

  const text = lines.join("\n");
  const html = lines
    .map((l) => {
      if (l.startsWith("  •")) return `<li>${l.slice(3)}</li>`;
      if (l.endsWith(":")) return `<p><strong>${l}</strong></p><ul>`;
      if (l === "") return "";
      return `<p>${l}</p>`;
    })
    .join("\n");

  return { subject, text, html: `<div>${html}</div>` };
}
