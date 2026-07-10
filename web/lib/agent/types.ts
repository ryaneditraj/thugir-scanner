/** Thugir Agent Engine scan types. */

export type AgentScanMode = "quick" | "standard" | "deep";

export interface AgentScanRequest {
  url: string;
  scan_mode?: AgentScanMode;
  command?: string;
  api_key?: string;
  base_url?: string;
  model?: string;
  provider?: string;
  timeout_seconds?: number;
}

export interface AgentFinding {
  title?: string;
  severity?: string;
  vuln_type?: string;
  description?: string;
  location?: string;
  evidence?: string;
  proof?: string;
  verified?: boolean;
  verification_status?: string;
  lifecycle_status?: string;
  remediation?: string;
  [key: string]: unknown;
}

export interface AgentScanResult {
  ok: boolean;
  target?: string;
  scan_mode?: AgentScanMode;
  exit_code?: number;
  exit_meaning?: string;
  summary?: Record<string, unknown>;
  findings?: AgentFinding[];
  finding_count?: number;
  report_path?: string | null;
  run_dir?: string | null;
  error?: string | null;
  stdout_tail?: string;
}

export interface AgentAvailability {
  available: boolean;
  python?: string;
  runner?: string;
  reason?: string;
}
