/**
 * Security regressions for the SSRF guard, login redirect, secret compare, and rate-limit fail mode.
 * Run: npx tsx scripts/test-security.ts
 */
import assert from "node:assert/strict";
import { isBlockedHostname, isBlockedIpAddress } from "../lib/checks/ssrf";
import { assertSafeFetchUrl, resolveSafeRedirect, BlockedTargetError } from "../lib/checks/http";
import { safeNextPath } from "../lib/auth/safe-next";
import { safeEqual } from "../lib/security/compare";
import { checkFreeScanLimit } from "../lib/ratelimit";

let passed = 0;
function check(name: string, fn: () => void | Promise<void>) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  ✓ ${name}`);
    });
}

const blockedHosts = [
  "127.0.0.1",
  "localhost",
  "localhost.",
  "10.1.2.3",
  "192.168.1.20",
  "172.16.5.5",
  "172.31.255.255",
  "169.254.169.254",
  "0.0.0.0",
  "0.0.0.1",
  "0177.0.0.1",
  "0x7f.0.0.1",
  "2130706433",
  "127.1",
  "::1",
  "::ffff:127.0.0.1",
  "::ffff:7f00:1",
  "fd00::1",
  "fe80::1",
  "metadata.google.internal",
  "app.internal",
  "printer.local",
  "intranet"
];

const publicHosts = ["example.com", "scan.example.co.uk", "1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"];

async function main() {
  for (const host of blockedHosts) {
    await check(`blocks ${host}`, () => {
      assert.equal(isBlockedHostname(host), true, host);
    });
  }
  for (const host of publicHosts) {
    await check(`allows ${host}`, () => {
      assert.equal(isBlockedHostname(host), false, host);
    });
  }

  await check("resolved loopback address is blocked", () => {
    assert.equal(isBlockedIpAddress("127.0.0.1"), true);
    assert.equal(isBlockedIpAddress("8.8.8.8"), false);
  });

  await check("octal and decimal readings of 0177 are both considered", () => {
    assert.equal(isBlockedHostname("0177.0.0.1"), true);
  });

  await check("normalize-style guard rejects metadata URL", async () => {
    await assert.rejects(() => assertSafeFetchUrl("http://169.254.169.254/latest/meta-data/"), BlockedTargetError);
  });

  await check("redirect to loopback is refused", () => {
    assert.throws(
      () => resolveSafeRedirect("https://example.com/start", "http://127.0.0.1/secret"),
      BlockedTargetError
    );
  });

  await check("redirect to metadata decimal IP is refused", () => {
    assert.throws(
      () => resolveSafeRedirect("https://example.com/start", "http://2852039166/latest/meta-data/"),
      BlockedTargetError
    );
  });

  await check("redirect to file URL is refused", () => {
    assert.throws(() => resolveSafeRedirect("https://example.com/start", "file:///etc/passwd"), BlockedTargetError);
  });

  await check("redirect to https on the same host is allowed", () => {
    const next = resolveSafeRedirect("http://example.com/a", "https://example.com/b");
    assert.equal(next.hostname, "example.com");
    assert.equal(next.pathname, "/b");
  });

  await check("names that resolve to loopback are refused", async () => {
    await assert.rejects(() => assertSafeFetchUrl("http://127.0.0.1.nip.io/"), BlockedTargetError);
  });

  await check("example.com resolves to a public address", async () => {
    const url = await assertSafeFetchUrl("https://example.com/");
    assert.equal(url.hostname, "example.com");
  });

  await check("safeNextPath stays on-site", () => {
    assert.equal(safeNextPath("/scans/abc?x=1"), "/scans/abc?x=1");
    assert.equal(safeNextPath("//evil.example"), "/dashboard");
    assert.equal(safeNextPath("/\\evil.example"), "/dashboard");
    assert.equal(safeNextPath("https://evil.example"), "/dashboard");
    assert.equal(safeNextPath(null), "/dashboard");
  });

  await check("safeEqual matches equal secrets only", () => {
    assert.equal(safeEqual("alpha", "alpha"), true);
    assert.equal(safeEqual("alpha", "alphb"), false);
    assert.equal(safeEqual("alpha", "alphabet"), false);
  });

  await check("production without Redis refuses free scans", async () => {
    const previous = process.env.NODE_ENV;
    const env = process.env as Record<string, string | undefined>;
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    env.NODE_ENV = "production";
    try {
      const decision = await checkFreeScanLimit("user", "203.0.113.5");
      assert.equal(decision.ok, false);
    } finally {
      env.NODE_ENV = previous;
    }
  });

  console.log(`\n${passed} security checks passed`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
