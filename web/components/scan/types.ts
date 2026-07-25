export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanFinding {
  id?: string;
  patternSlug?: string;
  category?: string;
  title: string;
  severity: Severity;
  tierRequired?: string;
  impactOneline: string;
  maxDamageOneline?: string;
  unlocked?: boolean;
  evidence?: Record<string, unknown>;
  remediation?: { summary: string; steps: string[] };
  fixPrompt?: string;
  status?: string;
}

export interface ScanAiSummary {
  summary: string;
  maxCompanyDamage?: string;
  attackChain?: string;
  riskLevel: string;
  model?: string;
}

export interface ScanMeta {
  totalFindings?: number;
  aiFindingsAdded?: number;
  probesRun?: number;
  pagesCrawled?: number;
}

export interface LockedPreview {
  checkCount: number;
  categories: string[];
}
