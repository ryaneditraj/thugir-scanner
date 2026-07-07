import type { PatternFinding, Severity } from "../patterns/types";

/** Worst realistic business outcome per confirmed pattern (static — always shown). */
export const MAX_DAMAGE_BY_SLUG: Record<string, string> = {
  "exposed-env-file":
    "Full account takeover across every service in the file — database wiped or sold, Stripe drained, email domain used for fraud, GDPR/CCPA breach notification to all users.",
  "exposed-config-backup":
    "Complete database dump downloadable: all customer PII, passwords, and payment records exfiltrated in one request — lawsuit, regulator fines, and forced shutdown.",
  "exposed-git-dir":
    "Entire source history stolen including every secret ever committed; attacker replays old API keys and finds unpublished admin backdoors.",
  "secret-stripe-live":
    "Unlimited charges and refunds on your merchant account, every customer's card data readable, business blacklisted by payment networks.",
  "secret-supabase-service-role":
    "Every row in your database readable, writable, and deletable without login — full customer data breach and ransomware-style wipe.",
  "supabase-service-role-in-bundle":
    "Every row in your database readable, writable, and deletable without login — full customer data breach and ransomware-style wipe.",
  "vibe-supabase-service-role-client":
    "Same as service_role leak: total database compromise from any visitor's browser.",
  "supabase-anon-key-no-rls":
    "Every user's private data (messages, health records, payments) readable and editable by anyone with your public anon key.",
  "supabase-rls-missing":
    "Every user's private data (messages, health records, payments) readable and editable by anyone with your public anon key.",
  "vibe-supabase-storage-public":
    "All uploaded files (IDs, medical docs, private photos) harvested and leaked; extortion and mandatory breach disclosure.",
  "vibe-demo-auth-bypass-flag":
    "Anyone becomes admin by toggling a flag in DevTools — full account takeover, data exfiltration, and reputational collapse.",
  "secret-aws-akid":
    "Cloud infrastructure owned: S3 buckets dumped, production servers terminated, six-figure AWS bill in hours.",
  "stack-database-url-in-bundle":
    "Direct SQL access to production — drop tables, steal every record, plant ransomware.",
  "firebase-open-rules":
    "Realtime database read/write for the world — user accounts hijacked, data vandalized, app unusable.",
  "vibe-firebase-firestore-open":
    "Customer records bulk-downloaded; competitors or criminals sell your user list.",
  "idor-sequential-ids":
    "Mass scraping of every user's private records by incrementing IDs — class-action privacy lawsuit territory.",
  "unprotected-webhook-endpoint":
    "Fake 'payment succeeded' events grant free premium to attackers and mark fake orders paid — direct revenue fraud.",
  "vibe-openapi-docs-exposed":
    "Attackers automate exploitation of every admin and mutation endpoint without guessing — faster full compromise.",
  "inline-state-secrets":
    "Keys visible in View Source are scraped by bots within minutes — automated draining of billing and email accounts.",
  "secret-openai":
    "Six-figure API bill overnight and your keys used to host phishing or malware campaigns tied to your account.",
  "secret-anthropic":
    "Runaway API spend and abuse of your account for malicious content generation.",
  "graphql-introspection-enabled":
    "Internal admin mutations discovered and invoked — privilege escalation and data exfil at scale.",
  "cors-reflect-origin":
    "Logged-in users' data stolen when they visit any malicious site while signed in — session-riding breach.",
  "permissive-cors":
    "Cross-site data theft from authenticated users' browsers — cookie/session abuse and API abuse.",
  "vibe-clerk-secret-in-client":
    "Full auth system compromise: create admin users, reset passwords, impersonate any customer.",
  "vibe-next-data-sensitive-keys":
    "Every page load ships secret config to the browser — full credential breach and mandatory rotation.",
  "vibe-unauthenticated-api-routes":
    "Mass automated scraping of customer/business data from your API without logging in.",
  "vibe-hardcoded-demo-credentials":
    "Default demo/admin credentials let attackers log in as staff — data theft, fraud, and full admin control.",
  "vibe-sitemap-sensitive-paths":
    "Hidden admin and staging URLs indexed and attacked first — bypasses your entire security-through-obscurity plan.",
  "vibe-weak-csp":
    "XSS on any page becomes full session theft — attackers drain accounts while users browse normally.",
  "vibe-streamlit-secrets-exposed":
    "Secrets in Streamlit config are scraped from the client — cloud keys and DB passwords compromised instantly.",
  "lovable-supabase-storage-public":
    "All user uploads in Supabase Storage harvested without authentication — PII leak and extortion risk.",
  "v0-server-action-no-authz":
    "Any visitor invokes privileged Server Actions directly — mass data deletion or unauthorized upgrades.",
  "lovable-client-only-auth":
    "Attackers bypass the UI entirely and read/write data via Supabase/API — total account takeover at scale.",
  "exposed-source-maps":
    "Unminified source reveals hidden admin routes, hardcoded secrets, and business logic flaws attackers chain into full breach.",
  "secret-convex-deploy-key":
    "Full Convex backend compromise: deploy malicious functions, read/write every document, and exfiltrate all user data."
};

const SEVERITY_FALLBACK: Record<Severity, string> = {
  critical:
    "Worst case: total data breach, regulatory fines (GDPR/CCPA), customer churn, payment processor termination, and founders personally liable.",
  high:
    "Worst case: major customer data exposure, account takeovers, mandatory breach notification, and six-figure incident response costs.",
  medium:
    "Worst case: targeted attacks using leaked intel, partial data exposure, and expensive emergency engineering sprints.",
  low:
    "Worst case: easier exploitation chained with other bugs; reconnaissance that accelerates a later breach.",
  info: "Worst case: aids a skilled attacker in planning a deeper attack against your company."
};

const CATEGORY_FALLBACK: Record<string, string> = {
  "Exposed secret":
    "Credentials abused within hours: financial theft, data exfiltration, and irreversible loss of customer trust.",
  "Broken access control":
    "Any user accesses any other user's data — mass privacy violation and regulatory enforcement.",
  "Broken authentication":
    "Widespread account takeover; attackers impersonate customers and staff.",
  "Information disclosure":
    "Attackers map your entire attack surface and hit the worst endpoint first.",
  "Security misconfiguration":
    "Combined with one other bug, leads to full application compromise.",
  "Source exposure":
    "Source and secrets leak enables a precision strike on production systems."
};

export function staticMaxDamage(f: Pick<PatternFinding, "patternSlug" | "severity" | "category">): string {
  return (
    MAX_DAMAGE_BY_SLUG[f.patternSlug] ||
    CATEGORY_FALLBACK[f.category] ||
    SEVERITY_FALLBACK[f.severity]
  );
}

export function applyStaticMaxDamage(findings: PatternFinding[]): PatternFinding[] {
  for (const f of findings) {
    if (!f.maxDamageOneline) f.maxDamageOneline = staticMaxDamage(f);
  }
  return findings;
}

export function overlayAiMaxDamage(
  findings: PatternFinding[],
  perSlug: Record<string, string> | undefined
): PatternFinding[] {
  if (!perSlug) return findings;
  for (const f of findings) {
    const ai = perSlug[f.patternSlug];
    if (ai) f.maxDamageOneline = ai;
  }
  return findings;
}
