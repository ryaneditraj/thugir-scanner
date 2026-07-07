import type { MetadataRoute } from "next";

const SITE = process.env.NEXT_PUBLIC_SITE_URL || "https://scanner.thugirlabs.com";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        // The admin surface must never be indexed or discovered via robots.
        disallow: ["/admin", "/admin/", "/dashboard", "/api/"]
      }
    ],
    sitemap: `${SITE}/sitemap.xml`
  };
}
