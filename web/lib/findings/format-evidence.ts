/** Turn heterogeneous evidence_json into readable report blocks. */

const SKIP_KEYS = new Set([
  "maxDamageOneline",
  "verdict",
  "proof",
  "evidence_verdict",
  "maxDamageOneline"
]);

const LABELS: Record<string, string> = {
  url: "URL",
  status: "HTTP status",
  bodySample: "Response sample",
  secretName: "Secret type",
  sampleRedacted: "Redacted sample",
  occurrences: "Occurrences",
  missing: "Missing headers",
  present: "Present headers",
  mapUrl: "Source map",
  projectUrl: "Project URL",
  openTables: "Open tables",
  note: "Note",
  payload: "Payload",
  param: "Parameter",
  source: "Source",
  cve_id: "CVE"
};

function labelFor(key: string): string {
  return LABELS[key] ?? key.replace(/_/g, " ");
}

function fmtValue(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(", ");
  return JSON.stringify(v, null, 2);
}

export interface FormattedEvidence {
  transcript: string | null;
  rows: { label: string; value: string }[];
}

export function formatEvidence(ev?: Record<string, unknown> | null): FormattedEvidence {
  if (!ev || typeof ev !== "object") return { transcript: null, rows: [] };

  const nested = ev.evidence;
  if (typeof nested === "string" && nested.trim()) {
    return { transcript: nested.trim(), rows: [] };
  }

  const url = typeof ev.url === "string" ? ev.url : null;
  const status = ev.status != null ? String(ev.status) : null;
  const body =
    typeof ev.bodySample === "string"
      ? ev.bodySample
      : typeof ev.response === "string"
        ? ev.response
        : null;

  let transcript: string | null = null;
  if (url || status || body) {
    const lines: string[] = [];
    if (url) lines.push(`$ GET ${url}`);
    if (status) lines.push(`< HTTP ${status}`);
    if (body) lines.push(body.slice(0, 1200));
    transcript = lines.join("\n");
  }

  const rows = Object.entries(ev)
    .filter(([k]) => !SKIP_KEYS.has(k) && k !== "evidence")
    .filter(([k]) => !(transcript && (k === "url" || k === "status" || k === "bodySample")))
    .map(([k, v]) => ({ label: labelFor(k), value: fmtValue(v) }))
    .filter((r) => r.value && r.value !== "—" && r.value !== "[]" && r.value !== "{}");

  return { transcript, rows };
}
