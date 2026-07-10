/** VulnClaw agent scan types (Thugir bridge). */

export type VulnClawScanMode = "quick" | "standard" | "deep";

export interface VulnClawScanRequest {
  url: string;
  scan_mode?: VulnClawScanMode;
  command?: string;
  api_key?: string;
  base_url?: string;
  model?: string;
  provider?: string;
  timeout_seconds?: number;
}

export interface VulnClawFinding {
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

export interface VulnClawScanResult {
  ok: boolean;
  target?: string;
  scan_mode?: VulnClawScanMode;
  exit_code?: number;
  exit_meaning?: string;
  summary?: Record<string, unknown>;
  findings?: VulnClawFinding[];
  finding_count?: number;
  report_path?: string | null;
  run_dir?: string | null;
  error?: string | null;
  stdout_tail?: string;
}

export interface VulnClawAvailability {
  available: boolean;
  python?: string;
  runner?: string;
  reason?: string;
}
