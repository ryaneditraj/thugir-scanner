/**
 * VulnClaw power checks — plugins, dir enum, reflexion probes ported to TypeScript.
 */
import type { FetchedDoc } from "./http";
import type { ProbeCache } from "./probe-cache";
import { decodeJwt, extractJwtCandidates } from "./crypto-tools";
import {
  escalatePayload,
  escalationLevelFromFailures,
  SQLI_PROBES,
  xssCanary,
  SSTI_PROBES
} from "../methodology/reflexion";

interface PowerCtx {
  origin: string;
  home: FetchedDoc;
  scripts: FetchedDoc[];
  combined: string;
  probe: ProbeCache;
}

interface PowerResult {
  fired: boolean;
  confidence: number;
  evidence: Record<string, unknown>;
}

type PowerRule = (ctx: PowerCtx) => Promise<PowerResult>;

const NEGATIVE: PowerResult = { fired: false, confidence: 0, evidence: {} };

// --- VulnClaw dir wordlist (compact subset) ---------------------------------
const DIR_WORDLIST = [
  "admin", "admin/login", "api", "api/v1", "graphql", "swagger", "swagger-ui.html",
  "openapi.json", "actuator", "actuator/health", "actuator/env", ".env", ".git/HEAD",
  "robots.txt", "debug", "phpinfo.php", "backup.zip", "upload", "console",
  "druid", "server-status", "v2/api-docs", "login", "auth", "internal", "manage"
];

const SENSITIVE_ENDPOINT_WORDS = ["admin", "debug", "internal", "graphql", "token", "secret"];

const ENDPOINT_RE =
  /["'`]((?:https?:\/\/[^"'`\s<>()]+|\/(?:api|admin|auth|graphql|v\d|static|assets|internal)[^"'`\s<>()]*))["'`]/gi;

// --- JWT claims in bundle (VulnClaw JWTClaimsPlugin) -------------------------
export const vulnclawJwtClaims: PowerRule = async (ctx) => {
  const tokens = extractJwtCandidates(ctx.combined, 6);
  if (!tokens.length) return NEGATIVE;

  const issues: Record<string, unknown>[] = [];
  for (const token of tokens) {
    const decoded = decodeJwt(token);
    if (!decoded) continue;
    const alg = String(decoded.header.alg ?? "").toLowerCase();
    const missing = ["exp", "iat", "iss", "aud"].filter((c) => !(c in decoded.payload));
    if (alg === "" || alg === "none") {
      issues.push({ alg: decoded.header.alg, issue: "unsigned_or_none_alg" });
    }
    if (missing.length >= 2) {
      issues.push({ missing_claims: missing, issue: "weak_validation_claims" });
    }
  }
  if (!issues.length) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.88,
    evidence: { tokens_analyzed: tokens.length, issues: issues.slice(0, 4), note: "JWT in client bundle with weak header/claims" }
  };
};

// --- JS sensitive endpoints (VulnClaw JavaScriptEndpointsPlugin) --------------
export const vulnclawJsEndpoints: PowerRule = async (ctx) => {
  const endpoints = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = ENDPOINT_RE.exec(ctx.combined))) {
    endpoints.add(m[1].replace(/[.,;]+$/, ""));
  }
  if (!endpoints.size) return NEGATIVE;
  const list = [...endpoints];
  const interesting = list.filter((e) => SENSITIVE_ENDPOINT_WORDS.some((w) => e.toLowerCase().includes(w)));
  if (!interesting.length) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.82,
    evidence: {
      endpoints: list.slice(0, 20),
      interesting_endpoints: interesting.slice(0, 10),
      note: "Sensitive API/admin endpoints referenced in client JavaScript"
    }
  };
};

// --- Directory enumeration (VulnClaw dir_enum subset) -------------------------
export const vulnclawDirEnum: PowerRule = async (ctx) => {
  const hits: { path: string; status: number; kind: string }[] = [];
  const urls = DIR_WORDLIST.map((p) => new URL(p, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 4096, redirect: "manual", timeoutMs: 6000 }, 6);

  for (const path of DIR_WORDLIST) {
    const url = new URL(path, ctx.origin).toString();
    const doc = docs.get(url);
    if (!doc) continue;
    if (doc.status === 403) {
      hits.push({ path, status: 403, kind: "exists_forbidden" });
      continue;
    }
    if (doc.status >= 200 && doc.status < 400) {
      const body = doc.body.slice(0, 2000);
      if (/Index of|openapi|swagger|actuator|phpinfo|admin login|graphql/i.test(body)) {
        hits.push({ path, status: doc.status, kind: "exposed_content" });
      } else if (path.includes("actuator") || path.includes("swagger") || path.includes(".git")) {
        hits.push({ path, status: doc.status, kind: "sensitive_path_2xx" });
      }
    }
  }
  if (!hits.length) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.85,
    evidence: { hits: hits.slice(0, 8), note: "Sensitive paths discovered via directory enumeration" }
  };
};

// --- Reflexion multi-encoding XSS -------------------------------------------
export const reflexionEscalatedXss: PowerRule = async (ctx) => {
  const suffix = "pwr";
  const base = xssCanary(suffix);
  const params = ["q", "search", "query", "name", "id", "term"];
  const paths = ["/", "/search", "/index.jsp"];
  let failures = 0;

  for (let level = 0 as 0 | 1 | 2 | 3; level <= 3; level++) {
    const payloads = escalatePayload(base, level);
    for (const param of params) {
      for (const path of paths) {
        for (const payload of payloads.slice(0, 3)) {
          const u = new URL(path, ctx.origin);
          u.searchParams.set(param, payload);
          const r = await ctx.probe.get(u.toString(), { maxBytes: 12000 });
          if (r.body.includes(payload) || r.body.includes(base)) {
            return {
              fired: true,
              confidence: 0.91,
              evidence: {
                url: u.toString(),
                param,
                escalation_level: level,
                note: "Reflected XSS canary echoed — WAF bypass may have succeeded at this encoding level"
              }
            };
          }
          failures++;
        }
      }
    }
  }
  return NEGATIVE;
};

// --- Reflexion SQLi with escalation -----------------------------------------
export const reflexionEscalatedSqli: PowerRule = async (ctx) => {
  const params = ["id", "user", "name", "q", "search"];
  const paths = ["/", "/api/users", "/search"];
  const sqlErrors =
    /SQL syntax|mysql_|postgresql|sqlite|ORA-\d{5}|unclosed quotation|odbc|syntax error/i;

  for (const base of SQLI_PROBES) {
    const level = escalationLevelFromFailures(0, 0);
    const payloads = escalatePayload(base, level);
    for (const param of params) {
      for (const path of paths) {
        for (const payload of payloads.slice(0, 4)) {
          const u = new URL(path, ctx.origin);
          u.searchParams.set(param, payload);
          const r = await ctx.probe.get(u.toString(), { maxBytes: 8192 });
          if (sqlErrors.test(r.body)) {
            return {
              fired: true,
              confidence: 0.9,
              evidence: {
                url: u.toString(),
                param,
                payload: payload.slice(0, 80),
                note: "SQL error triggered by escalated injection probe"
              }
            };
          }
        }
      }
    }
  }
  return NEGATIVE;
};

// --- Reflexion SSTI multi-template ------------------------------------------
export const reflexionEscalatedSsti: PowerRule = async (ctx) => {
  const params = ["name", "q", "template", "message", "content"];
  const paths = ["/", "/search", "/template"];

  for (const expr of SSTI_PROBES) {
    const level = escalationLevelFromFailures(0, 0);
    for (const payload of escalatePayload(expr, level).slice(0, 3)) {
      for (const param of params) {
        for (const path of paths) {
          const u = new URL(path, ctx.origin);
          u.searchParams.set(param, payload);
          const r = await ctx.probe.get(u.toString(), { maxBytes: 8192 });
          if (r.body.includes("49") && (payload.includes("7*7") || payload.includes("7*7"))) {
            return {
              fired: true,
              confidence: 0.92,
              evidence: {
                url: u.toString(),
                probe: payload,
                note: "Template engine evaluated arithmetic (49) — SSTI with reflexion encoding"
              }
            };
          }
        }
      }
    }
  }
  return NEGATIVE;
};

export const VULNCLAW_POWER_RULES = {
  vulnclawJwtClaims,
  vulnclawJsEndpoints,
  vulnclawDirEnum,
  reflexionEscalatedXss,
  reflexionEscalatedSqli,
  reflexionEscalatedSsti
} as const;
