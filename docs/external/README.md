# External (public) documentation + SEO surfaces

These are the public, statically-generated pages. They build trust (transparency for a security
product) and feed the SEO/content strategy. All link back to the scanner CTA.

Implemented pages (in `web/app/(marketing)/`):
- `/how-scans-work` - exactly what the free scan and Deep Scan do, and what we never do.
- `/platforms/[platform]` - per-builder guides (Lovable, Bolt, v0, Replit, Cursor, Windsurf, Supabase, Firebase) sourced from the pattern library.
- `/report/sample` - a redacted sample Deep Scan report.
- `/verify/[badgeId]` - public verification page for the "scanned & passed" trust badge.
- `/demo` - interactive sample.

- `/vulnerabilities/[slug]` - one page per pattern (auto from pattern library).

Planned SEO surfaces:
- `/checklists/[platform]` - pre-launch security checklists.
- `/compare/[a-vs-b]` - builder security comparison pages.

Metadata/OG tags are set per page via `generateMetadata`. `sitemap.ts` enumerates every page
(including one URL per pattern). `robots.ts` allows all marketing routes and disallows
`/admin`, `/dashboard`, `/api`.

## Content sourcing
The vulnerability/platform/checklist pages render directly from the pattern library
(`web/lib/patterns`), so adding a pattern automatically creates/extends SEO pages. Comparison
pages are hand-authored in `web/app/(marketing)/compare/[slug]/page.tsx`.

## Trust badge
Embed snippet (give to customers who pass a scan):
```html
<a href="https://scanner.thugirlabs.com/verify/SCAN_ID">
  <img src="https://scanner.thugirlabs.com/badge/SCAN_ID.svg" alt="Scanned by Thugir" />
</a>
```
The verification page shows only a pass/attention summary - never the findings.
