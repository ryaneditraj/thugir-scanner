# Launch kit

Copy for a public intro and a short demo. Say only what this repository does.

## One-liner

Thugir Scanner finds misconfigurations AI coding tools leave in a web app, and it reports a finding only when the check captured proof.

## Hooks that match the code

- A free-tier finding is returned only when the check captured a positive signal.
- Deep-tier evidence is omitted from the free JSON. It is not hidden with CSS.
- The page at `/demo` is an in-memory fixture. The hits are the detectors in this repo. Nothing is fetched.
- Private, loopback, link-local, and metadata addresses are refused, including obfuscated IP forms and redirects.
- The homepage counts are `patternsForTier("free")` and the enabled rows in `STATIC_PATTERNS`.

## Do not say

- User counts, customers, funding, CVEs found, accuracy rates, or years of research.
- That a scan takes ten seconds, or that Deep Scan takes a fixed number of minutes.
- The scoreboard numbers on thugirlabs.com (`critical_precision`, `web80`, `cve_bench_mock`, `bountybench`, `false_critical`) as results of this scanner.
- That `/demo` is a scan of a real company. The paste from that page starts with `SYNTHETIC FIXTURE`.
- Prices, until you have confirmed the defaults in admin settings (`$0`, `$29 / scan`, `$99 / month` are the values shipped in code).

## Storyboard

About twenty seconds. No third-party target.

1. Open the homepage. Read the line under the headline. Those are library counts.
2. Open **Labeled sample**. Point at the banner before you point at a finding.
3. Open the first hit. The redacted sample is what the detector returned on the invented bundle.
4. Copy the summary. Show that the first line says `SYNTHETIC FIXTURE`.
5. Stop. Do not scan a site you do not own.

## Still blocking a public launch

- The Hack Club API key that was rewritten out of git history still needs to be rotated. Do not assume that happened. Merged pull requests #43, #44, and #45 may still show it in GitHub's stored diffs.
- This repository is private until you change visibility. Do not treat a local demo as a public launch.
- `https://scanner.thugirlabs.com` returned HTTP 404 when last checked. The marketing site at `https://www.thugirlabs.com` returned 200. The app still defaults `NEXT_PUBLIC_SITE_URL` to the scanner host.
- Next.js stays on 14.2.35. `npm audit` wants 16.4.5, which changes `cookies()` and middleware. That upgrade is not in this branch. See `SECURITY.md`.
- Deep Scan still needs a separate `thugir-node` checkout. It is not in this repository.
