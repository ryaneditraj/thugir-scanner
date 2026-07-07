import type { FetchedDoc } from "../checks/http";
import type { Platform } from "../patterns/types";

// AI-builder fingerprinting. We look for telltale scaffolding signatures so Deep Scan can
// prioritize the right platform's pattern set first. Signals are intentionally conservative.
interface Signature {
  platform: Platform;
  test: (ctx: { home: FetchedDoc; combined: string }) => boolean;
}

const SIGNATURES: Signature[] = [
  {
    platform: "lovable",
    test: ({ home, combined }) =>
      /lovable/i.test(home.headers["x-powered-by"] || "") ||
      /lovable\.(?:dev|app)|gptengineer/i.test(combined)
  },
  { platform: "bolt", test: ({ combined }) => /bolt\.new|stackblitz/i.test(combined) },
  { platform: "v0", test: ({ combined }) => /v0\.dev|v0-built/i.test(combined) },
  { platform: "replit", test: ({ combined }) => /replit|repl\.co|janeway/i.test(combined) },
  { platform: "base44", test: ({ combined }) => /base44/i.test(combined) },
  {
    platform: "cursor",
    test: ({ combined }) => /cursor\.sh|cursor-ide|generated.with.cursor/i.test(combined)
  },
  {
    platform: "windsurf",
    test: ({ combined }) => /windsurf|codeium/i.test(combined)
  },
  {
    platform: "firebase",
    test: ({ combined }) => /firebaseapp\.com|firebaseio\.com|firebase\/app/i.test(combined)
  },
  {
    platform: "supabase",
    test: ({ combined }) => /supabase\.co|@supabase\/supabase-js/i.test(combined)
  },
  {
    platform: "generic",
    test: ({ combined }) => /convex\.cloud|@convex\/dev/i.test(combined)
  },
  {
    platform: "generic",
    test: ({ combined }) => /streamlit|st\.components/i.test(combined)
  }
];

export interface DetectionResult {
  platform: Platform | null;
  signals: Platform[];
}

export function detectPlatform(home: FetchedDoc, combined: string): DetectionResult {
  const signals: Platform[] = [];
  for (const sig of SIGNATURES) {
    try {
      if (sig.test({ home, combined })) signals.push(sig.platform);
    } catch {
      /* ignore */
    }
  }
  // Prefer the builder over the backend SDK when both are present.
  const builderOrder: Platform[] = [
    "lovable",
    "bolt",
    "v0",
    "replit",
    "cursor",
    "windsurf",
    "base44"
  ];
  const builder = builderOrder.find((p) => signals.includes(p));
  return { platform: builder ?? signals[0] ?? null, signals };
}
