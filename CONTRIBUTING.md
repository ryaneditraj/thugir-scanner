# Contributing

Thanks for looking at Thugir Scanner. The useful change is a check that captures proof, or a fix that makes an existing check harder to bypass.

## Ground rules

- Test only systems you are authorized to test.
- Do not commit secrets, tokens, `.env` files, or personal contact details.
- Do not add user counts, benchmark scores, customer names, or funding claims unless they are already verifiable from this repository.
- Keep `services/thugir-agent` (VulnClaw, copyright UncleC) under its own MIT license. Do not relicense that tree.

## Setup

Requirements: Node.js 20 or newer, and Python 3.11 or newer for the worker tests.

```bash
npm install --prefix web
cp web/.env.example web/.env.local
```

For a local UI without Supabase, set these in `web/.env.local`:

```bash
DEV_MODE=1
DEV_TIER=free
NEXT_PUBLIC_SITE_URL=http://localhost:3000
```

`DEV_MODE` is ignored when `NODE_ENV=production`.

```bash
npm test
npm run demo
npm run dev
```

`npm test` runs the web harnesses and the worker unit tests. `npm run demo` runs the free-tier secret detector and the server-side blur gate against a synthetic bundle. `npm run scan -- https://example.com` runs the free-tier engine against one authorized URL.

## What to change

- Free-tier checks live in `web/lib/checks` and `web/lib/patterns`. A free-tier rule should require positive evidence. Guesses belong in the deep tier, where the product already withholds them from free responses.
- The SSRF guard is `web/lib/checks/ssrf.ts` plus `assertSafeFetchUrl` in `web/lib/checks/http.ts`. Add a regression to `web/scripts/test-security.ts` when you change it.
- The worker's target check is `worker/target_guard.py`.
- Pattern catalog: `npm --prefix web run patterns`.

## Pull requests

Use the pull request template. Run `npm test` and `npm run typecheck` before asking for review. `npm run lint` uses the Next.js ESLint config in `web/.eslintrc.json`.

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports go through [SECURITY.md](SECURITY.md), not a public issue.
