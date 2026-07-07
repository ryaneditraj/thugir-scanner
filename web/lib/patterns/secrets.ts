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
    slug: "secret-openai",
    name: "OpenAI API key",
    regex: "sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "Your OpenAI key can be used to run up usage charges on your account."
  },
  {
    slug: "secret-anthropic",
    name: "Anthropic API key",
    regex: "sk-ant-[A-Za-z0-9_-]{20,}",
    severity: "high",
    serverOnly: true,
    impact: "Your Anthropic key can be abused to bill your account."
  },
  {
    slug: "secret-stripe-live",
    name: "Stripe live secret key",
    regex: "sk_live_[A-Za-z0-9]{20,}",
    severity: "critical",
    serverOnly: true,
    impact: "A Stripe live secret key allows charges, refunds and reading customer data."
  },
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
  }
];

export const twilioLiveCredentialPattern: Pattern = {
  slug: "secret-twilio",
  platform: "generic",
  category: "Exposed secret",
  severityDefault: "critical",
  title: "Live Twilio credentials exposed in client bundle",
  description:
    "A Twilio account SID and auth token were found together in JavaScript or HTML served to the browser, and a harmless read against Twilio's Accounts API confirmed the credentials are live. AI SMS/OTP scaffolds often ship Twilio client SDK init with real keys.",
  impactOneline: "Live Twilio credentials let anyone send SMS/calls on your bill.",
  detectorKind: "rule_ref",
  detectorConfig: { rule: "twilioLiveCredentialProbe" },
  tierRequired: "free",
  remediation: {
    summary: "Rotate the Twilio auth token now and move credentials server-side.",
    steps: [
      "Rotate the Twilio auth token in the Twilio console immediately.",
      "Remove accountSid and authToken from all client code and client-exposed env vars (NEXT_PUBLIC_*, VITE_*).",
      "Proxy SMS/OTP through a server route that holds the Twilio credentials."
    ]
  },
  fixPrompt:
    "Live Twilio credentials (accountSid + authToken) are exposed in my client bundle and validated as active. Remove them from all client-side code and client-exposed environment variables, move every Twilio call into server-side code, and tell me exactly which files referenced them so I can rotate the auth token.",
  version: 1,
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
  twilioLiveCredentialPattern
];
