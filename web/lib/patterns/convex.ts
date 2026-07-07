import type { Pattern } from "./types";

// Convex patterns. Convex queries are public HTTP endpoints by default; AI scaffolds often
// forget ctx.auth.getUserIdentity() checks, leaking real rows to anonymous callers.
export const convexPatterns: Pattern[] = [
  {
    slug: "convex-open-query-no-auth",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "critical",
    title: "Convex query returns data without authentication",
    description:
      "Every Convex query is exposed at POST /api/query on your deployment URL. AI-built apps frequently ship list/get queries without an auth check, so anyone who finds your deployment URL in the bundle can read user data.",
    impactOneline:
      "Anonymous callers can read your Convex database through an unauthenticated query.",
    detectorKind: "rule_ref",
    detectorConfig: {
      rule: "convexOpenQuery",
      options: { harmlessProbe: true }
    },
    tierRequired: "free",
    remediation: {
      summary: "Add ctx.auth.getUserIdentity() checks to every public Convex query.",
      steps: [
        "Audit every query in your convex/ folder for missing auth checks.",
        "Throw or return null when ctx.auth.getUserIdentity() is absent on sensitive queries.",
        "Use internalQuery for server-only functions and keep public queries owner-scoped.",
        "Re-test by calling POST /api/query without an Authorization header."
      ]
    },
    fixPrompt:
      "My Convex deployment has queries that return data without authentication. Audit every query function, add ctx.auth.getUserIdentity() checks on sensitive reads, scope results to the authenticated user, and show the updated code for each fixed query.",
    version: 1,
    enabled: true
  }
];
