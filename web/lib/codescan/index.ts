import type { Severity } from "../patterns/types";
import { CODE_RULES } from "./rules";
import { fetchRepoFiles, RepoError } from "./github";

export { RepoError };

export interface CodeFinding {
  ruleId: string;
  title: string;
  category: string;
  severity: Severity;
  impact: string;
  fix: string;
  file: string;
  line: number;
  snippet: string;
}

export interface CodeScanResult {
  repo: string;
  branch: string;
  filesScanned: number;
  totalFiles: number;
  truncated: boolean;
  findings: CodeFinding[];
  countsBySeverity: Record<string, number>;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const MAX_MATCHES_PER_RULE_PER_FILE = 3;
const MAX_TOTAL_FINDINGS = 150;

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === "\n") line++;
  return line;
}

function snippetAt(text: string, index: number): string {
  const start = text.lastIndexOf("\n", index) + 1;
  let end = text.indexOf("\n", index);
  if (end === -1) end = text.length;
  return text.slice(start, end).trim().slice(0, 200);
}

export async function runRepoScan(repoUrl: string): Promise<CodeScanResult> {
  const repo = await fetchRepoFiles(repoUrl);
  const findings: CodeFinding[] = [];

  outer: for (const file of repo.files) {
    for (const rule of CODE_RULES) {
      if (rule.exts && !rule.exts.includes(file.ext)) continue;
      const re = new RegExp(rule.regex.source, rule.regex.flags.includes("g") ? rule.regex.flags : rule.regex.flags + "g");
      let m: RegExpExecArray | null;
      let hits = 0;
      while ((m = re.exec(file.content)) !== null) {
        if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loop
        const matched = m[0];
        if (rule.reject && rule.reject(matched)) continue;
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          impact: rule.impact,
          fix: rule.fix,
          file: file.path,
          line: lineOf(file.content, m.index),
          snippet: snippetAt(file.content, m.index)
        });
        if (++hits >= MAX_MATCHES_PER_RULE_PER_FILE) break;
        if (findings.length >= MAX_TOTAL_FINDINGS) break outer;
      }
    }
  }

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.file.localeCompare(b.file)
  );

  const countsBySeverity: Record<string, number> = {};
  for (const f of findings) countsBySeverity[f.severity] = (countsBySeverity[f.severity] ?? 0) + 1;

  return {
    repo: `${repo.ref.owner}/${repo.ref.repo}`,
    branch: repo.ref.branch,
    filesScanned: repo.scanned,
    totalFiles: repo.totalBlobs,
    truncated: repo.truncated,
    findings,
    countsBySeverity
  };
}
