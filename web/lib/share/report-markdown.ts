import { formatEvidence } from "../findings/format-evidence";

export interface ReportFinding {
  title: string;
  severity: string;
  impactOneline: string;
  unlocked?: boolean;
  evidence?: Record<string, unknown>;
}

// Plain-text card a creator can paste. Synthetic runs are labeled on the first line so the
// paste cannot be read as a scan of a live site.
export function reportMarkdown(input: {
  synthetic: boolean;
  target: string;
  detectedPlatform: string | null;
  findings: ReportFinding[];
}): string {
  const lines: string[] = [];
  if (input.synthetic) {
    lines.push("SYNTHETIC FIXTURE — not a scan of a live site.");
    lines.push("Detector output from the Thugir free-tier engine on an invented page.");
  } else {
    lines.push("Thugir Scanner — free-tier result.");
    lines.push("A finding is listed only when that check captured evidence.");
  }
  lines.push(`Target: ${input.target}`);
  if (input.detectedPlatform) lines.push(`Stack signal: ${input.detectedPlatform}`);
  lines.push("");
  const unlocked = input.findings.filter((f) => f.unlocked !== false);
  if (!unlocked.length) {
    lines.push("No confirmed findings in this result.");
  }
  unlocked.forEach((f, i) => {
    lines.push(`${i + 1}. [${f.severity}] ${f.title}`);
    lines.push(`   ${f.impactOneline}`);
    if (f.evidence) {
      const { transcript, rows } = formatEvidence(f.evidence);
      if (transcript) lines.push(`   Evidence: ${transcript.replace(/\s+/g, " ").slice(0, 280)}`);
      for (const row of rows) lines.push(`   ${row.label}: ${row.value}`);
    }
    lines.push("");
  });
  return lines.join("\n").trim() + "\n";
}
