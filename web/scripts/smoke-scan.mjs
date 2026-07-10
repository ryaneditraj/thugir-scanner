#!/usr/bin/env node
/** Integration smoke: POST /api/scan/free against local dev server. */
const url = process.argv[2] || "https://petstore.swagger.io";
const base = process.env.SCAN_BASE || "http://localhost:3000";

async function main() {
  const res = await fetch(`${base}/api/scan/free`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, attest: true })
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    console.error("FAIL", res.status, "non-JSON response (is the dev server on port 3000?)");
    console.error(text.slice(0, 200));
    process.exit(1);
  }
  if (!res.ok) {
    console.error("FAIL", res.status, data.error || data);
    process.exit(1);
  }
  console.log("OK", data.target, "| findings:", data.findings?.length ?? 0);
  if (data.meta) console.log("meta:", JSON.stringify(data.meta));
  if (data.ai?.attackChain) console.log("attackChain:", data.ai.attackChain.slice(0, 120) + "...");
  const withDamage = (data.findings || []).filter((f) => f.maxDamageOneline);
  console.log("with max damage:", withDamage.length);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
