import type { Pattern } from "./types";

// Supabase patterns. These are the single highest-yield class of finding in AI-built apps:
// the builder scaffolds a client with the anon key and forgets Row Level Security, or ships
// the service_role key into the client bundle.
export const supabasePatterns: Pattern[] = [
  {
    slug: "supabase-service-role-in-bundle",
    platform: "supabase",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Supabase service_role key shipped to the browser",
    description:
      "The Supabase service_role key bypasses Row Level Security entirely. AI builders sometimes wire it into client code or an exposed env var because they put .env access on the client by default. Anyone can read and write every row in your database.",
    impactOneline:
      "Full read/write access to your entire database for anyone who views your site source.",
    detectorKind: "secret_regex",
    detectorConfig: {
      // service_role JWTs are standard JWTs whose payload contains "role":"service_role".
      regex: "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}",
      validate: "service_role",
      secretName: "Supabase service_role key",
      serverOnly: true
    },
    tierRequired: "free",
    remediation: {
      summary: "Remove the service_role key from all client code and rotate it immediately.",
      steps: [
        "Rotate the service_role key in Supabase > Project Settings > API.",
        "Delete any client-side usage; only use it in server-side code (route handlers / Edge functions).",
        "Use the anon key on the client and rely on Row Level Security for access control."
      ]
    },
    fixPrompt:
      "My Supabase service_role key is exposed in the client bundle. Remove every client-side use of the service_role key, switch the browser client to the anon key, and move any privileged database access into server-side route handlers. Then list every place the service_role key was referenced so I can confirm it is gone.",
    version: 1,
    enabled: true
  },
  {
    slug: "supabase-anon-key-no-rls",
    platform: "supabase",
    category: "Broken access control",
    severityDefault: "high",
    title: "Supabase anon key exposed with Row Level Security disabled",
    description:
      "Exposing the anon key client-side is expected and safe ONLY when Row Level Security protects every table. AI builders frequently create tables without enabling RLS, so the anon key alone can read or write data.",
    impactOneline:
      "Visitors may be able to read or modify your data directly, with no login.",
    detectorKind: "rule_ref",
    detectorConfig: {
      rule: "supabaseRls",
      options: { harmlessProbe: true }
    },
    tierRequired: "free",
    remediation: {
      summary: "Enable Row Level Security on every table and add owner-scoped policies.",
      steps: [
        "In Supabase, enable RLS on each table under Authentication > Policies.",
        "Add policies that restrict rows to the authenticated owner (e.g. user_id = auth.uid()).",
        "Re-test by querying with the anon key while signed out."
      ]
    },
    fixPrompt:
      "Some of my Supabase tables have Row Level Security disabled, so the public anon key can read/write them. Enable RLS on every table and generate owner-scoped policies (rows visible only to the authenticated owner). Output the SQL for each policy.",
    version: 1,
    enabled: true
  }
];
