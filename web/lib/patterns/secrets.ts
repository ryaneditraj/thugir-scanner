import type { Pattern } from "./types";

// Curated, high-precision secret patterns scoped to what AI builders actually leak.
// Deliberately NOT a kitchen-sink list: false positives kill trust on a free tool.
// Each entry has a distinctive prefix/shape so a raw match is high-confidence.
interface SecretDef {
  slug: string;
  name: string;
  regex: string;
  validate?: string;
  severity: Pattern["severityDefault"];
  serverOnly?: boolean;
  impact: string;
}

const SECRET_DEFS: SecretDef[] = [
  {
    slug: "secret-stripe-restricted",
    name: "Stripe restricted key",
    regex: "rk_live_[A-Za-z0-9]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "A Stripe restricted key exposes whatever scopes it was granted."
  },
  {
    slug: "secret-aws-akid",
    name: "AWS access key id",
    regex: "AKIA[0-9A-Z]{16}",
    severity: "critical",
    serverOnly: true,
    impact: "An AWS access key can expose cloud resources, storage and billing."
  },
  {
    slug: "secret-resend",
    name: "Resend API key",
    regex: "re_[A-Za-z0-9_]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "A Resend key lets attackers send email as your domain (phishing risk)."
  },
  {
    slug: "secret-sendgrid",
    name: "SendGrid API key",
    regex: "SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}",
    severity: "high",
    serverOnly: true,
    impact: "A SendGrid key lets attackers send email as your domain."
  },
  {
    slug: "secret-supabase-service-role",
    name: "Supabase service_role JWT",
    regex: "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}",
    validate: "service_role",
    severity: "critical",
    serverOnly: true,
    impact: "The service_role key bypasses all database security."
  },
  {
    slug: "secret-google-oauth",
    name: "Google OAuth client secret",
    regex: "GOCSPX-[A-Za-z0-9_-]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "A Google OAuth client secret can enable account-takeover flows."
  },
  {
    slug: "secret-github-pat",
    name: "GitHub personal access token",
    regex: "ghp_[A-Za-z0-9]{36}",
    severity: "critical",
    serverOnly: true,
    impact: "A GitHub token can expose private source code and CI secrets."
  },
  {
    slug: "secret-github-fine",
    name: "GitHub fine-grained token",
    regex: "github_pat_[A-Za-z0-9_]{22,}",
    severity: "critical",
    serverOnly: true,
    impact: "A GitHub token can expose private source code and CI secrets."
  },
  {
    slug: "secret-slack",
    name: "Slack token",
    regex: "xox[baprs]-[A-Za-z0-9-]{10,}",
    severity: "high",
    serverOnly: true,
    impact: "A Slack token can read/post in your workspace."
  },
  {
    slug: "secret-razorpay",
    name: "Razorpay key secret",
    regex: "rzp_(?:live|test)_[A-Za-z0-9]{14,}",
    severity: "high",
    serverOnly: true,
    impact: "Razorpay credentials can expose payment operations."
  },
  {
    slug: "secret-private-key",
    name: "Private key block",
    regex: "-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    severity: "critical",
    serverOnly: true,
    impact: "A private key in the bundle can fully compromise the associated service."
  },
  {
    slug: "secret-linear",
    name: "Linear API key",
    regex: "lin_api_[A-Za-z0-9]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "A Linear API key exposes your workspace issues and internal data."
  },
  {
    slug: "secret-paddle",
    name: "Paddle API key",
    regex: "pdl_(?:live|test)_[A-Za-z0-9]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "Paddle credentials can expose billing and customer data."
  },
  {
    slug: "secret-mapbox-sk",
    name: "Mapbox secret access token",
    regex: "sk\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
    severity: "high",
    serverOnly: true,
    impact: "A Mapbox secret token can create charges, read private datasets, and modify your maps account."
  },
  {
    slug: "secret-sentry-auth",
    name: "Sentry user auth token",
    regex: "sntrys_[A-Za-z0-9_=-]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "A Sentry auth token can read error data, change project settings, and access org secrets."
  },
  {
    slug: "secret-posthog-personal",
    name: "PostHog personal API key",
    regex: "phx_[A-Za-z0-9]{32,}",
    severity: "high",
    serverOnly: true,
    impact: "A PostHog personal API key can export analytics data and change project configuration."
  },
  {
    slug: "secret-shopify-admin",
    name: "Shopify Admin API access token",
    regex: "shpat_[a-fA-F0-9]{32}",
    severity: "critical",
    serverOnly: true,
    impact: "A Shopify Admin API token can read orders, customers, and modify your store."
  },
  {
    slug: "secret-hasura-admin",
    name: "Hasura admin secret",
    regex: 'x-hasura-admin-secret["\']?\\s*:\\s*["\']([A-Za-z0-9]{20,})["\']',
    severity: "critical",
    serverOnly: true,
    impact: "A Hasura admin secret bypasses all GraphQL/Postgres authorization rules."
  },
  {
    slug: "secret-convex-deploy-key",
    name: "Convex deploy key",
    regex: "(?:dev|prod):[a-z0-9-]+\\|[A-Za-z0-9+/=_-]{20,}|(?:preview|project):[a-z0-9-]+:[a-z0-9-]+\\|[A-Za-z0-9+/=_-]{20,}",
    severity: "critical",
    serverOnly: true,
    impact: "A Convex deploy key grants full read/write/deploy control over your backend."
  }
];

export const openaiLiveKeyPattern: Pattern = {
  slug: "secret-openai",
  platform: "generic",
  category: "Exposed secret",
  severityDefault: "high",
  title: "OpenAI API key exposed in client bundle",
  description:
    "An OpenAI API key (sk-* / sk-proj-*) was found in JavaScript or HTML served to the browser, and a harmless read against OpenAI's Models API confirmed the key is active. AI scaffolds routinely ship OPENAI_API_KEY via NEXT_PUBLIC_* or VITE_* env vars.",
  impactOneline: "Your OpenAI key can be used to run up usage charges on your account.",
  detectorKind: "rule_ref",
  detectorConfig: { rule: "openaiLiveKeyProbe" },
  tierRequired: "free",
  remediation: {
    summary: "Rotate the OpenAI API key now and move it server-side.",
    steps: [
      "Revoke and create a new API key in the OpenAI dashboard immediately.",
      "Remove OPENAI_API_KEY from all client code and client-exposed env vars (NEXT_PUBLIC_*, VITE_*).",
      "Call OpenAI only from server-side code (route handlers / serverless functions)."
    ]
  },
  fixPrompt:
    "An OpenAI API key is exposed in my client bundle and validated as active. Remove it from all client-side code and client-exposed environment variables, move every OpenAI call into server-side code, and tell me exactly which files referenced it so I can rotate the key.",
  version: 1,
  enabled: true
};

export const anthropicLiveKeyPattern: Pattern = {
  slug: "secret-anthropic",
  platform: "generic",
  category: "Exposed secret",
  severityDefault: "high",
  title: "Anthropic API key exposed in client bundle",
  description:
    "An Anthropic API key (sk-ant-*) was found in JavaScript or HTML served to the browser, and a harmless read against Anthropic's Models API confirmed the key is active. AI scaffolds routinely ship ANTHROPIC_API_KEY via NEXT_PUBLIC_* or VITE_* env vars.",
  impactOneline: "Your Anthropic key can be abused to bill your account.",
  detectorKind: "rule_ref",
  detectorConfig: { rule: "anthropicLiveKeyProbe" },
  tierRequired: "free",
  remediation: {
    summary: "Rotate the Anthropic API key now and move it server-side.",
    steps: [
      "Revoke and create a new API key in the Anthropic console immediately.",
      "Remove ANTHROPIC_API_KEY from all client code and client-exposed env vars (NEXT_PUBLIC_*, VITE_*).",
      "Call Anthropic only from server-side code (route handlers / serverless functions)."
    ]
  },
  fixPrompt:
    "An Anthropic API key is exposed in my client bundle and validated as active. Remove it from all client-side code and client-exposed environment variables, move every Anthropic call into server-side code, and tell me exactly which files referenced it so I can rotate the key.",
  version: 1,
  enabled: true
};

export const stripeLiveKeyPattern: Pattern = {
  slug: "secret-stripe-live",
  platform: "generic",
  category: "Exposed secret",
  severityDefault: "critical",
  title: "Live Stripe secret key exposed in client bundle",
  description:
    "A Stripe live secret key (sk_live_*) was found in JavaScript or HTML served to the browser, and a harmless read against Stripe's Balance API confirmed the key is active. AI payment scaffolds routinely ship Stripe server keys via NEXT_PUBLIC_* or VITE_* env vars.",
  impactOneline: "A live Stripe secret key allows charges, refunds and reading customer data.",
  detectorKind: "rule_ref",
  detectorConfig: { rule: "stripeLiveKeyProbe" },
  tierRequired: "free",
  remediation: {
    summary: "Rotate the Stripe secret key now and move it server-side.",
    steps: [
      "Roll the secret key in the Stripe dashboard immediately.",
      "Remove sk_live_* from all client code and client-exposed env vars (NEXT_PUBLIC_*, VITE_*).",
      "Use Stripe publishable keys (pk_live_*) in the browser and keep secret keys in server routes only."
    ]
  },
  fixPrompt:
    "A live Stripe secret key (sk_live_*) is exposed in my client bundle and validated as active. Remove it from all client-side code and client-exposed environment variables, move every Stripe server call into server-side code, and tell me exactly which files referenced it so I can rotate the key.",
  version: 1,
  enabled: true
};

// Twilio uses rule_ref (not regex) — Account SIDs alone are too noisy; we require auth token pairing.
export const twilioCredentialPattern: Pattern = {
  slug: "secret-twilio",
  platform: "generic",
  category: "Exposed secret",
  severityDefault: "high",
  title: "Twilio account SID + auth token exposed in client bundle",
  description:
    "A Twilio account SID paired with its auth token was found in JavaScript or HTML served to the browser. AI SMS/OTP scaffolds often import the full Twilio client with both credentials on the client side.",
  impactOneline: "Twilio credentials can be abused to send SMS/calls on your bill.",
  detectorKind: "rule_ref",
  detectorConfig: { rule: "twilioCredentialsInClient" },
  tierRequired: "free",
  remediation: {
    summary: "Rotate the Twilio auth token now and move credentials server-side.",
    steps: [
      "Rotate the Twilio auth token in the Twilio console immediately.",
      "Remove accountSid and authToken from all client code and client-exposed env vars.",
      "Proxy SMS/OTP sends through a server route that holds the credentials."
    ]
  },
  fixPrompt:
    "My Twilio account SID and auth token are exposed in the client bundle. Move all Twilio API calls to server-side code, remove TWILIO_AUTH_TOKEN from any NEXT_PUBLIC_/VITE_ env vars, and show me exactly which files referenced the credentials so I can rotate the auth token.",
  version: 2,
  enabled: true
};

export const secretPatterns: Pattern[] = [
  ...SECRET_DEFS.map(
    (s): Pattern => ({
      slug: s.slug,
      platform: "generic",
      category: "Exposed secret",
      severityDefault: s.severity,
      title: `${s.name} exposed in client bundle`,
      description: `A ${s.name} was found in JavaScript or HTML served to the browser. AI builders often place .env access on the client side by default, shipping server secrets to every visitor.`,
      impactOneline: s.impact,
      detectorKind: "secret_regex",
      detectorConfig: {
        regex: s.regex,
        validate: s.validate,
        secretName: s.name,
        serverOnly: s.serverOnly
      },
      tierRequired: "free",
      remediation: {
        summary: `Rotate the ${s.name} now and move it server-side.`,
        steps: [
          "Treat the key as compromised and rotate it with the provider immediately.",
          "Remove it from all client code and from any client-exposed env var (e.g. NEXT_PUBLIC_*, VITE_*).",
          "Access the key only from server-side code (route handlers / serverless functions)."
        ]
      },
      fixPrompt: `A ${s.name} is exposed in my client bundle. Remove it from all client-side code and client-exposed environment variables, move every use of it into server-side code, and tell me exactly which files referenced it so I can rotate and confirm.`,
      version: 1,
      enabled: true
    })
  ),
  openaiLiveKeyPattern,
  anthropicLiveKeyPattern,
  stripeLiveKeyPattern
];
