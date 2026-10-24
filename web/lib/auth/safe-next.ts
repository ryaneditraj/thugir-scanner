const FALLBACK = "/dashboard";

/**
 * Post-login path. Protocol-relative (`//evil`) and backslash forms are rejected
 * so a `next` query param cannot leave this origin when it is later joined to the site URL.
 */
export function safeNextPath(raw: string | null | undefined): string {
  if (!raw) return FALLBACK;
  const value = raw.trim();
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\") || value.includes("\\")) {
    return FALLBACK;
  }
  try {
    const base = "https://thugir.invalid";
    const url = new URL(value, base);
    if (url.origin !== base) return FALLBACK;
    return `${url.pathname}${url.search}${url.hash}` || FALLBACK;
  } catch {
    return FALLBACK;
  }
}
