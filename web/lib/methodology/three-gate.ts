/**
 * Three-gate confirmation adapted from CyberStrike common-prompt.txt
 * @see docs/reference/cyberstrike/vendor/prompts/common-prompt.txt
 */

export interface GateEvidence {
  baseline?: { status?: number; snippet?: string };
  exploit?: { status?: number; snippet?: string };
  diff?: string;
}

/** Reject findings where exploit was blocked or diff is absent. */
export function passesThreeGate(evidence: GateEvidence): boolean {
  const exploitStatus = evidence.exploit?.status;
  if (exploitStatus === 401 || exploitStatus === 403) return false;

  const diff = (evidence.diff || "").trim();
  if (!diff) return false;

  const blocked = /forbidden|unauthorized|access denied|not allowed/i;
  if (blocked.test(diff) && exploitStatus && exploitStatus >= 400) return false;

  return true;
}

export const THREE_GATE_PROMPT = `Before reporting ANY vulnerability you MUST satisfy three gates:
Gate 1 BASELINE — benign/unmodified request + response
Gate 2 EXPLOIT — attack payload request + response YOU sent
Gate 3 DIFF — measurable difference (data access, execution evidence, state change)
If exploit returns 403/401, or baseline equals exploit, it is NOT a vulnerability.
Include baseline snippet, exploit snippet, and one-sentence diff in evidence.`;
