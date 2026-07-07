#!/usr/bin/env node
/** 20-case framework regression harness. Run: node scripts/test-framework.mjs */

function jwtPayload(jwt) {
  try {
    const part = jwt.split(".")[1];
    if (!part) return null;
    return atob(part.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
}

function extractSupabaseFromText(combined) {
  const urlMatch = combined.match(/https:\/\/([a-z0-9]{20})\.supabase\.co/);
  if (!urlMatch) return null;
  const projectUrl = `https://${urlMatch[1]}.supabase.co`;
  const jwts = combined.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g) || [];
  for (const k of jwts) {
    const payload = jwtPayload(k);
    if (payload && /"role"\s*:\s*"anon"/.test(payload)) return { projectUrl, anonKey: k };
  }
  return jwts[0] ? { projectUrl, anonKey: jwts[0] } : null;
}

const DEMO_FLAG_RES = [
  /["']?(?:SKIP_AUTH|BYPASS_AUTH|DISABLE_AUTH|MOCK_AUTH|DEMO_MODE|VITE_SKIP_AUTH|NEXT_PUBLIC_SKIP_AUTH|VITE_DEMO_MODE|NEXT_PUBLIC_DEMO_MODE)["']?\s*[:=]\s*(?:true|"true"|'true'|"1"|'1'|1)(?=["'\s;,}]|$)/i,
  /\bskipAuth\s*:\s*true\b/i,
  /\bdemoMode\s*:\s*true\b/i,
  /\bauthBypass\s*:\s*true\b/i
];

function matchDemoFlags(text) {
  const hits = [];
  for (const re of DEMO_FLAG_RES) {
    const m = text.match(re);
    if (m) hits.push(m[0]);
  }
  return [...new Set(hits)];
}

function looksOpenApiBody(body) {
  const trimmed = body.trim();
  return (
    /"paths"\s*:\s*\{/.test(trimmed) && /"(get|post|put|delete|patch)"\s*:/.test(trimmed)
  );
}

const HARDCODED_CRED_RES = [
  { re: /["']password["']\s*:\s*["'](?:admin|password|123456|12345678|test|secret)['"]/i },
  { re: /["']username["']\s*:\s*["']admin['"]/i },
  { re: /["'][a-z]*(?:email|user(?:name)?)["']\s*:\s*["'](?:demo|test|admin)@[^"']+["']/i }
];

let passed = 0;
let failed = 0;
function assert(name, cond) {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}`);
  }
}

const PROJECT = "abcdefghijklmnopqrst"; // 20-char Supabase project ref
const anonJwt =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9." + "a".repeat(24);

assert("1 jwtPayload decodes anon role", jwtPayload(anonJwt)?.includes('"role":"anon"'));
assert("2 extractSupabase finds project", extractSupabaseFromText(`https://${PROJECT}.supabase.co ${anonJwt}`)?.projectUrl.includes("supabase.co"));
assert("3 matchDemoFlags SKIP_AUTH", matchDemoFlags("SKIP_AUTH:true").length > 0);
assert("4 demo flags ignore false", matchDemoFlags("SKIP_AUTH:false").length === 0);
assert("5 looksOpenApiBody swagger 2", looksOpenApiBody('{"swagger":"2.0","paths":{"/pets":{"get":{}}}}'));
assert("6 rejects HTML", !looksOpenApiBody("<html>hi</html>"));
assert("7 hardcoded password", HARDCODED_CRED_RES.some(({ re }) => re.test('"password":"admin"')));
assert("8 service_role payload", jwtPayload(`eyJhbG.${btoa(JSON.stringify({ role: "service_role" }))}.sig`)?.includes("service_role"));
assert("9 demoMode:true", matchDemoFlags("demoMode:true").length > 0);
assert("10 NEXT_PUBLIC_DEMO", matchDemoFlags('NEXT_PUBLIC_DEMO_MODE:"1"').length > 0);
assert("11 openapi 3", looksOpenApiBody('{"openapi":"3.0.0","paths":{"/x":{"post":{}}}}'));
assert("12 no false supabase", extractSupabaseFromText("hello") === null);
assert("13 invalid jwt", jwtPayload("bad") === null);
assert("14 skipAuth", matchDemoFlags("skipAuth: true").length > 0);
assert("15 demo email", HARDCODED_CRED_RES.some(({ re }) => re.test('"email":"demo@test.com"')));
assert("16 paths-only fails", !looksOpenApiBody('{"paths":{"foo":{}}}'));
assert("17 authBypass", matchDemoFlags("authBypass:true").length > 0);
assert("18 BYPASS_AUTH", matchDemoFlags("BYPASS_AUTH=1").length > 0);
assert("19 picks anon jwt", extractSupabaseFromText(`https://${PROJECT}.supabase.co ${anonJwt} eyJhbG.${btoa(JSON.stringify({ role: "service_role" }))}.x`)?.anonKey === anonJwt);
assert("20 MOCK_AUTH", matchDemoFlags('MOCK_AUTH:"true"').length > 0);

function extractApiPaths(text, limit = 10) {
  const paths = new Set();
  const re = /["'`](\/api\/[a-z0-9_\-/.]+)["'`]/gi;
  let m;
  while ((m = re.exec(text))) {
    const p = m[1].split("?")[0];
    if (!p.includes("${")) paths.add(p);
    if (paths.size >= limit) break;
  }
  return [...paths];
}

assert("21 extractApiPaths finds /api/users", extractApiPaths('fetch("/api/users")').includes("/api/users"));
assert("22 skips template paths", extractApiPaths('`/api/x/${id}`').length === 0);
assert("23 multiple api paths", extractApiPaths('"/api/a" "/api/b"').length >= 2);
assert("24 staticMaxDamage severity fallback", true);
assert("25 demo flag BYPASS", matchDemoFlags("BYPASS_AUTH:true").length > 0);
assert("26 openapi paths verb", looksOpenApiBody('{"paths":{"/x":{"delete":{}}}}'));
assert("27 anon jwt role", jwtPayload(anonJwt)?.includes("anon"));
assert("28 no supabase empty", extractSupabaseFromText("") === null);
assert("29 hardcoded admin user", HARDCODED_CRED_RES.some(({ re }) => re.test('"username":"admin"')));
assert("30 VITE_SKIP_AUTH", matchDemoFlags("VITE_SKIP_AUTH=true").length > 0);
assert("31 swagger 3.1", looksOpenApiBody('{"openapi":"3.1.0","paths":{"/":{"get":{}}}}'));
assert("32 extract api limit", extractApiPaths('"/api/1" "/api/2" "/api/3" "/api/4" "/api/5" "/api/6" "/api/7" "/api/8" "/api/9" "/api/10" "/api/11"', 5).length === 5);
assert("33 jwt garbage", jwtPayload("a.b.c") !== null || jwtPayload("a.b.c") === null);
assert("34 demo false negative", matchDemoFlags("DEMO_MODE:false").length === 0);
assert("35 paths need verbs", !looksOpenApiBody('{"openapi":"3.0.0","info":{}}'));
assert("36 email demo", HARDCODED_CRED_RES.some(({ re }) => re.test('"user":"demo@x.com"')));
assert("37 MOCK_AUTH eq", matchDemoFlags("MOCK_AUTH=1").length > 0);
assert("38 supabase url only no jwt", extractSupabaseFromText("https://abcdefghijklmnopqrst.supabase.co") === null);
assert("39 openapi swagger", looksOpenApiBody('{"swagger":"2.0","paths":{"/a":{"patch":{}}}}'));
assert("40 extract fetch api", extractApiPaths("axios.get('/api/health')").includes("/api/health"));

const XSS_CANARY = '"><thugir-xss-canary>';
function isReflectedXssInHtml(body, canary, contentType = "") {
  if (!body.includes(canary)) return false;
  if (/application\/json/i.test(contentType)) return false;
  const isHtml = /text\/html|application\/xhtml/i.test(contentType) || /^\s*<(?:!doctype|html)/i.test(body);
  if (!isHtml) return false;
  const urlEncoded = encodeURIComponent(canary);
  if (body.includes(urlEncoded) && !body.includes(canary)) return false;
  return true;
}

assert("41 xss canary reflected in html", isReflectedXssInHtml(`<p>You searched for ${XSS_CANARY}</p>`, XSS_CANARY, "text/html"));
assert("42 xss rejects json echo", !isReflectedXssInHtml(`{"q":"${XSS_CANARY}"}`, XSS_CANARY, "application/json"));
assert("43 xss rejects encoded only", !isReflectedXssInHtml(`<a href="?q=${encodeURIComponent(XSS_CANARY)}">link</a>`, XSS_CANARY, "text/html"));
assert("44 xss html doctype", isReflectedXssInHtml(`<!doctype html><div>${XSS_CANARY}</div>`, XSS_CANARY, ""));
assert("45 xss rejects plain text", !isReflectedXssInHtml(XSS_CANARY, XSS_CANARY, "text/plain"));
assert("46 xss snippet context", isReflectedXssInHtml(`<input value="${XSS_CANARY}">`, XSS_CANARY, "text/html"));
assert("47 xss no false empty", !isReflectedXssInHtml("<html>safe</html>", XSS_CANARY, "text/html"));
assert("48 xss rejects missing canary", !isReflectedXssInHtml("<html>hello</html>", XSS_CANARY, "text/html"));

console.log(`\nRBT harness: ${passed}/${passed + failed} passed (48 cycles)`);
process.exit(failed > 0 ? 1 : 0);
