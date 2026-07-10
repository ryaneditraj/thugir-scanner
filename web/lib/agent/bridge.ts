import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import type { AgentAvailability, AgentScanRequest, AgentScanResult } from "./types";

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dir, "../../..");
const AGENT_ROOT = join(REPO_ROOT, "services/thugir-agent");
const RUNNER = join(AGENT_ROOT, "thugir_runner.py");

function findPython(): string | null {
  const candidates = [
    process.env.THUGIR_AGENT_PYTHON,
    process.env.PYTHON,
    "python3",
    "python"
  ].filter(Boolean) as string[];

  for (const bin of candidates) {
    const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 5000 });
    if (r.status === 0) return bin;
  }
  return null;
}

/** Check if the Thugir Agent Engine can run in this environment. */
export function agentAvailability(): AgentAvailability {
  const python = findPython();
  if (!python) {
    return { available: false, reason: "Python 3.10+ not found (set THUGIR_AGENT_PYTHON)" };
  }
  if (!existsSync(RUNNER)) {
    return { available: false, python, reason: `Missing runner at ${RUNNER}` };
  }
  if (!existsSync(join(AGENT_ROOT, "vulnclaw"))) {
    return { available: false, python, reason: "Thugir Agent Engine package not installed" };
  }
  return { available: true, python, runner: RUNNER };
}

/** Run a headless Thugir Agent Engine scan. Requires local Python + LLM API key. */
export function runAgentScan(req: AgentScanRequest): AgentScanResult {
  const avail = agentAvailability();
  if (!avail.available || !avail.python) {
    return { ok: false, error: avail.reason || "Thugir Agent Engine unavailable" };
  }

  const payload: AgentScanRequest = {
    scan_mode: "quick",
    timeout_seconds: 600,
    ...req,
    api_key:
      req.api_key ||
      process.env.THUGIR_AGENT_LLM_API_KEY ||
      process.env.OPENAI_API_KEY ||
      process.env.ANTHROPIC_API_KEY,
    base_url: req.base_url || process.env.THUGIR_AGENT_LLM_BASE_URL || process.env.OPENAI_BASE_URL,
    model: req.model || process.env.THUGIR_AGENT_LLM_MODEL,
    provider: req.provider || process.env.THUGIR_AGENT_LLM_PROVIDER || "openai"
  };

  const timeoutMs = (payload.timeout_seconds || 600) * 1000 + 30_000;

  const proc = spawnSync(avail.python, [RUNNER], {
    cwd: AGENT_ROOT,
    input: JSON.stringify(payload),
    encoding: "utf8",
    timeout: timeoutMs,
    env: {
      ...process.env,
      PYTHONPATH: AGENT_ROOT,
      VULNCLAW_CONFIG_DIR: join(AGENT_ROOT, ".thugir-config"),
      VULNCLAW_RUNS_DIR: join(AGENT_ROOT, ".thugir-runs")
    }
  });

  if (proc.error) {
    return { ok: false, error: proc.error.message, target: req.url };
  }

  const stdout = (proc.stdout || "").trim();
  if (!stdout) {
    return {
      ok: false,
      error: "empty runner output",
      target: req.url,
      stdout_tail: (proc.stderr || "").slice(-1500)
    };
  }

  try {
    return JSON.parse(stdout) as AgentScanResult;
  } catch {
    return {
      ok: false,
      error: "invalid JSON from thugir_runner",
      target: req.url,
      stdout_tail: stdout.slice(-1500)
    };
  }
}

export const AGENT_ROOT_PATH = AGENT_ROOT;
