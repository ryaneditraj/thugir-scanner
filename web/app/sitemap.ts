import type { MetadataRoute } from "next";
import { STATIC_PATTERNS } from "@/lib/patterns";

const SITE = process.env.NEXT_PUBLIC_SITE_URL || "https://scanner.thugirlabs.com";

const PLATFORMS = [
  "lovable",
  "bolt",
  "v0",
  "replit",
  "cursor",
  "windsurf",
  "supabase",
  "firebase"
];

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();
  const staticPaths = ["/", "/demo", "/how-scans-work", "/report/sample", "/terms", "/privacy"];
  const platformPaths = PLATFORMS.map((p) => `/platforms/${p}`);
  const vulnPaths = STATIC_PATTERNS.filter((p) => p.enabled).map((p) => `/vulnerabilities/${p.slug}`);

  return [...staticPaths, ...platformPaths, ...vulnPaths].map((path) => ({
    url: `${SITE}${path}`,
    lastModified: now,
    changeFrequency: "weekly" as const,
    priority:
      path === "/" ? 1 : path.startsWith("/platforms") || path.startsWith("/vulnerabilities") ? 0.8 : 0.7
  }));
}
