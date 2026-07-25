#!/usr/bin/env node
/**
 * Integration test suite — run against local dev server (npm run dev).
 * Usage: node scripts/integration-test.mjs [baseUrl]
 */
import { execSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dir = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = resolve(__dir, "..");
const BASE = process.argv[2] || process.env.SCAN_BASE || "http://localhost:3000";

const results = [];
let failed = 0;

function pass(name, detail = "") {
  results.push({ name, ok: true, detail });
  console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ""}`);
}

function fail(name, detail = "") {
  results.push({ name, ok: false, detail });
  failed++;
  console.error(`  ✕ ${name}${detail ? ` — ${detail}` : ""}`);
}

async function get(path, expectStatus = 200) {
  const res = await fetch(`${BASE}${path}`);
  const text = await res.text();
  if (res.status !== expectStatus) {
    throw new Error(`GET ${path} expected ${expectStatus}, got ${res.status}: ${text.slice(0, 120)}`);
  }
  return { res, text };
}

async function post(path, body, expectStatus = 200) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { _raw: text };
  }
  if (res.status !== expectStatus) {
    throw new Error(
      `POST ${path} expected ${expectStatus}, got ${res.status}: ${JSON.stringify(data).slice(0, 200)}`
    );
  }
  return { res, data };
}

async function runSuite(round) {
  console.log(`\n═══ Round ${round} ═══`);

  // --- Health ---
  try {
    const res = await fetch(`${BASE}/api/health`);
    const data = await res.json();
    if (!res.ok || data.ok !== true) fail("GET /api/health", `status=${res.status}`);
    else pass("GET /api/health", `mode=${data.mode}`);
  } catch (e) {
    fail("GET /api/health", String(e.message || e));
  }

  // --- Pages ---
  const pages = ["/", "/demo", "/dashboard", "/login", "/verify/demo", "/how-scans-work"];
  for (const p of pages) {
    try {
      const { res } = await get(p);
      if (!res.ok) fail(`GET ${p}`, `status ${res.status}`);
      else pass(`GET ${p}`, `${res.status}`);
    } catch (e) {
      fail(`GET ${p}`, String(e.message || e));
    }
  }

  // --- Free scan (happy path) ---
  try {
    const { data } = await post("/api/scan/free", { url: "petstore.swagger.io", attest: true });
    if (!data.target) fail("POST /api/scan/free", "missing target");
    else if (!Array.isArray(data.findings)) fail("POST /api/scan/free", "findings not array");
    else {
      pass("POST /api/scan/free", `${data.findings.length} findings, tier=${data.tier ?? "free"}`);
      if (data.findings.length > 0) {
        const f = data.findings[0];
        if (!f.title || !f.severity) fail("free scan finding shape", "missing title/severity");
        else pass("free finding shape", f.severity);
      }
    }
  } catch (e) {
    fail("POST /api/scan/free", String(e.message || e));
  }

  // --- Free scan validation ---
  try {
    await post("/api/scan/free", { url: "petstore.swagger.io" }, 400);
    pass("POST /api/scan/free no attest", "400 as expected");
  } catch (e) {
    fail("POST /api/scan/free no attest", String(e.message || e));
  }

  try {
    await post("/api/scan/free", { url: "http://127.0.0.1", attest: true }, 400);
    pass("POST /api/scan/free SSRF block", "400 as expected");
  } catch (e) {
    fail("POST /api/scan/free SSRF block", String(e.message || e));
  }

  // --- Deep run (DEV_MODE + DEV_TIER=deep) ---
  try {
    const { data } = await post("/api/scan/deep-run", { url: "petstore.swagger.io" });
    if (!data.target) fail("POST /api/scan/deep-run", "missing target");
    else if (!Array.isArray(data.findings)) fail("POST /api/scan/deep-run", "findings not array");
    else pass("POST /api/scan/deep-run", `${data.findings.length} findings, scanId=${data.scanId ?? "null"}`);
  } catch (e) {
    fail("POST /api/scan/deep-run", String(e.message || e));
  }

  // --- Evidence formatter (unit, no server) ---
  try {
    execSync(
      `npx tsx -e "import { formatEvidence } from './lib/findings/format-evidence'; const r=formatEvidence({url:'https://x.com',status:200,bodySample:'ok'}); if(!r.transcript) process.exit(1);"`,
      { cwd: WEB_ROOT, stdio: "pipe" }
    );
    pass("formatEvidence");
  } catch (e) {
    fail("formatEvidence", String(e.message || e).slice(0, 120));
  }
}

async function main() {
  const rounds = Number(process.env.TEST_ROUNDS || "3");
  console.log(`Integration tests → ${BASE} (${rounds} rounds)`);

  for (let r = 1; r <= rounds; r++) {
    await runSuite(r);
  }

  const total = results.length;
  const ok = results.filter((x) => x.ok).length;
  console.log(`\n══════════════════════════════════`);
  console.log(`Results: ${ok}/${total} passed across ${rounds} round(s)`);
  if (failed > 0) {
    console.error(`FAILED: ${failed} assertion(s)`);
    process.exit(1);
  }
  console.log("All integration checks passed.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
