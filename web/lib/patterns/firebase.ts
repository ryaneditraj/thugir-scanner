import type { Pattern } from "./types";

// Firebase patterns. The default-open security rules from the AI quickstart template are
// the classic Firebase leak. The web config object is not itself a secret, but open rules
// turn it into a full data breach.
export const firebasePatterns: Pattern[] = [
  {
    slug: "firebase-open-firestore-rules",
    platform: "firebase",
    category: "Broken access control",
    severityDefault: "critical",
    title: "Firestore / Realtime DB rules left open",
    description:
      "AI builders commonly ship the Firebase quickstart rules `allow read, write: if true;`. Combined with the public web config, anyone can read and write your entire database.",
    impactOneline: "Anyone on the internet can read and overwrite your database.",
    detectorKind: "rule_ref",
    detectorConfig: {
      rule: "firebaseRules",
      options: { harmlessProbe: true }
    },
    tierRequired: "free",
    remediation: {
      summary: "Replace permissive rules with auth- and ownership-scoped rules.",
      steps: [
        "Open the Firebase console > Firestore/Realtime Database > Rules.",
        "Remove any `if true` allow rule.",
        "Require request.auth != null and scope documents to request.auth.uid."
      ]
    },
    fixPrompt:
      "My Firebase security rules are open (allow read, write: if true). Rewrite the Firestore (and Realtime Database, if present) rules so reads/writes require authentication and are scoped to the document owner via request.auth.uid. Output the complete rules file.",
    version: 1,
    enabled: true
  },
  {
    slug: "firebase-config-exposed",
    platform: "firebase",
    category: "Information exposure",
    severityDefault: "info",
    title: "Firebase web config present in bundle",
    description:
      "The Firebase web config (apiKey, projectId, etc.) is intentionally public, but its presence tells an attacker to test your security rules. This is informational unless rules are open.",
    impactOneline:
      "Reveals your Firebase project so attackers can probe its rules. Safe only if rules are locked down.",
    detectorKind: "secret_regex",
    detectorConfig: {
      regex: "AIza[0-9A-Za-z_\\-]{35}",
      secretName: "Firebase web API key"
    },
    tierRequired: "free",
    version: 1,
    enabled: true
  }
];
