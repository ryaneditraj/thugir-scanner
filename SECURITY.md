# Security policy

Thugir Scanner sends real HTTP requests to a URL you supply. Use it only on systems you own or are explicitly authorized to test.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/ryaneditraj/thugir-scanner/security/advisories/new) for this repository.

Please include the affected path, a short proof, and the impact. Do not open a public issue for an unfixed vulnerability.

TODO(Ryan): publish a dedicated security contact email. This file does not list a personal address.

## What this tree enforces

- The free-tier fetcher refuses non-http(s) URLs, loopback, private, link-local, and cloud-metadata hosts, including obfuscated IPv4 forms (decimal, hex, octal, short dotted, IPv4-mapped IPv6). If either the octal or the decimal reading of a leading-zero octet is non-public, the host is blocked.
- Redirects are followed manually. Each hop is checked again, including a DNS lookup, so a public URL that redirects to `127.0.0.1` or `169.254.169.254` is not fetched.
- Names that resolve only to non-public addresses are refused. A 15 second process cache avoids a lookup on every probe of the same host. A DNS rebinding inside that window is a residual limitation.
- `DEV_MODE=1` does not bypass auth when `NODE_ENV=production`.
- Free scans and admin login throttles fail closed in production when Upstash Redis is not configured. Local development still runs without Redis.
- Worker callbacks and cron bearer tokens are compared in constant time.
- The Python worker rejects unsigned jobs unless `ALLOW_UNSIGNED_JOBS=1`, and it rejects private targets before a Deep Scan starts.
- Razorpay webhooks are checked against the raw body with an HMAC.

## Secrets removed from history

A Hack Club AI API key (prefix `sk-hc-v1-`) was committed in `web/config/hackathon.env` and later deleted from the tip. The value was rewritten out of git history. **Rotate that key** at Hack Club. Any copy that was cloned before the rewrite should be treated as exposed. The key is not reprinted here.

No phone number, age, school, or street address for the maintainer was found in the tree. The Gmail address previously used as a commit author was rewritten to the GitHub noreply address. Do not put personal contact details back into the repository.

## Known dependency advisories

`npm audit` reports Next.js advisories whose patched release is 16.4.5, a semver major. This app stays on Next.js 14.2.35. The production server does not use `next/image`. Auth still calls synchronous `cookies()` from `next/headers`, and request gating lives in `middleware.ts`. Jumping to 16 changes both of those APIs, so it is a separate change, not part of the launch pass. TODO(Ryan): upgrade to Next.js 16.4.5 or newer and re-run `npm audit`.

The critical Next.js advisories in that audit are remote code execution in the image optimizer (AVIF and SVG) and on Windows-hosted servers. The high advisories include server-component denial of service, middleware bypass on the Pages Router with i18n, and server-action issues. Treat the 14 line as unpatched until the upgrade lands.

`puppeteer-core` is a dev dependency used by lab checks. Its transitive advisories currently require a major upgrade. It is not part of the production server path.

## Scope

This policy covers the code in this repository. It does not cover third-party training sites the scanner can be pointed at, the optional VulnClaw tree under `services/thugir-agent` beyond its own license, or a `thugir-node` checkout that is not stored here.
