import type { Severity } from "../patterns/types";

// Static-analysis rules for source code. These target the mistakes that AI coding assistants
// ship most often: hard-coded secrets, command/SQL injection sinks, disabled TLS, unsafe
// deserialization, and XSS-prone DOM writes. Each rule is a precise regex with a clear fix.
//
// Rules are intentionally high-precision (low false-positive) — we would rather miss a fuzzy
// case than cry wolf, matching the "evidence-gated" promise of the URL scanner.

export interface CodeRule {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  impact: string;
  fix: string;
  regex: RegExp;
  // Optional extension allow-list (lowercase, no dot). Omitted = all code files.
  exts?: string[];
  // Optional guard to drop obvious placeholders / false positives.
  reject?: (match: string) => boolean;
}

const PLACEHOLDER = /(your[_-]?|example|placeholder|xxxx|0000|<.*>|changeme|dummy|test|sample|redacted|\*\*\*)/i;

export const CODE_RULES: CodeRule[] = [
  {
    id: "aws-access-key",
    title: "Hard-coded AWS access key",
    category: "Secret exposure",
    severity: "critical",
    impact: "An AWS access key id committed to source grants attackers direct access to your cloud account.",
    fix: "Remove the key from source, load it from an environment variable or secrets manager, and rotate it in IAM immediately.",
    regex: /AKIA[0-9A-Z]{16}/g
  },
  {
    id: "google-api-key",
    title: "Hard-coded Google API key",
    category: "Secret exposure",
    severity: "high",
    impact: "A committed Google API key can be abused to run up billing or access enabled APIs.",
    fix: "Move the key to an env var, restrict it by referrer/IP/API in the Google console, and rotate it.",
    regex: /AIza[0-9A-Za-z_\-]{35}/g
  },
  {
    id: "stripe-secret-key",
    title: "Hard-coded Stripe secret key",
    category: "Secret exposure",
    severity: "critical",
    impact: "A live Stripe secret key lets an attacker move money and read customer/payment data.",
    fix: "Delete the key from source, load it from an env var on the server only, and roll it in the Stripe dashboard.",
    regex: /sk_live_[0-9a-zA-Z]{16,}/g
  },
  {
    id: "private-key-block",
    title: "Private key committed to source",
    category: "Secret exposure",
    severity: "critical",
    impact: "An embedded private key (TLS/SSH/JWT signing) lets an attacker impersonate your service.",
    fix: "Remove the key, store it in a secrets manager, and rotate the corresponding credential/certificate.",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g
  },
  {
    id: "slack-token",
    title: "Hard-coded Slack token",
    category: "Secret exposure",
    severity: "high",
    impact: "A Slack token can be used to read messages and act as your bot/app.",
    fix: "Remove the token from source, load from an env var, and revoke + reissue it in Slack.",
    regex: /xox[baprs]-[0-9A-Za-z-]{10,48}/g
  },
  {
    id: "generic-secret-assignment",
    title: "Hard-coded secret in source",
    category: "Secret exposure",
    severity: "medium",
    impact: "A literal password/secret/api-key assigned in code leaks to anyone with repo access.",
    fix: "Replace the literal with an environment variable and rotate the value.",
    regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\b\s*[:=]\s*["'][^"'\s]{6,}["']/gi,
    reject: (m) => PLACEHOLDER.test(m)
  },
  {
    id: "jwt-hardcoded-secret",
    title: "Hard-coded JWT signing secret",
    category: "Secret exposure",
    severity: "high",
    impact: "A static JWT secret in source lets an attacker forge valid tokens for any user.",
    fix: "Load the signing secret from an env var, use a long random value, and rotate it.",
    regex: /\b(?:jwt[_-]?secret|jwt[_-]?key|signing[_-]?secret)\b\s*[:=]\s*["'][^"']{8,}["']/gi,
    reject: (m) => PLACEHOLDER.test(m)
  },
  {
    id: "eval-use",
    title: "Use of eval()",
    category: "Code injection",
    severity: "high",
    impact: "eval() on any attacker-influenced string is remote code execution.",
    fix: "Remove eval(). Parse JSON with JSON.parse and use explicit logic instead of dynamic evaluation.",
    regex: /\beval\s*\(/g,
    exts: ["js", "jsx", "ts", "tsx", "mjs", "cjs", "py"]
  },
  {
    id: "node-exec",
    title: "Shell execution sink",
    category: "Command injection",
    severity: "high",
    impact: "Building a shell command from user input enables command injection (full server takeover).",
    fix: "Avoid the shell: use execFile/spawn with an argument array and never interpolate user input into a command string.",
    regex: /\b(?:exec|execSync)\s*\(\s*[`"'][^`"']*\$\{/g,
    exts: ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
  },
  {
    id: "py-os-system",
    title: "os.system() call",
    category: "Command injection",
    severity: "high",
    impact: "os.system() with interpolated input is command injection.",
    fix: "Use subprocess.run([...]) with a list of args and shell=False; never format user input into the command.",
    regex: /\bos\.system\s*\(/g,
    exts: ["py"]
  },
  {
    id: "py-subprocess-shell",
    title: "subprocess with shell=True",
    category: "Command injection",
    severity: "high",
    impact: "shell=True with interpolated input allows command injection.",
    fix: "Pass a list of arguments and use shell=False (the default).",
    regex: /subprocess\.(?:call|run|Popen|check_output)\([^)]*shell\s*=\s*True/g,
    exts: ["py"]
  },
  {
    id: "react-dangerous-html",
    title: "dangerouslySetInnerHTML",
    category: "Cross-site scripting",
    severity: "medium",
    impact: "Rendering unsanitised HTML leads to stored/reflected XSS.",
    fix: "Render text instead of HTML, or sanitise with a vetted library (e.g. DOMPurify) before injecting.",
    regex: /dangerouslySetInnerHTML/g,
    exts: ["js", "jsx", "ts", "tsx"]
  },
  {
    id: "dom-innerhtml",
    title: "Assignment to innerHTML",
    category: "Cross-site scripting",
    severity: "medium",
    impact: "Writing untrusted data to innerHTML executes injected markup/scripts (XSS).",
    fix: "Use textContent for text, or sanitise HTML before assignment.",
    regex: /\.innerHTML\s*=\s*[^;]*(?:\$\{|\+|req\.|input|params|query)/g,
    exts: ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
  },
  {
    id: "sql-concat-js",
    title: "SQL built by string concatenation",
    category: "SQL injection",
    severity: "high",
    impact: "Concatenating input into SQL allows injection and full database compromise.",
    fix: "Use parameterised queries / prepared statements; never build SQL with + or template literals from input.",
    regex: /(?:query|execute)\s*\(\s*[`"'][^`"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`"']*(?:\$\{|["']\s*\+)/gi,
    exts: ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
  },
  {
    id: "sql-fstring-py",
    title: "SQL built with an f-string",
    category: "SQL injection",
    severity: "high",
    impact: "An f-string interpolating input into SQL is injectable.",
    fix: "Use parameterised queries (cursor.execute(sql, params)); never f-string user input into SQL.",
    regex: /execute\s*\(\s*f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{/gi,
    exts: ["py"]
  },
  {
    id: "cors-wildcard",
    title: "CORS allows any origin",
    category: "Security misconfiguration",
    severity: "medium",
    impact: "A wildcard CORS origin lets any site make authenticated cross-origin requests to your API.",
    fix: "Set an explicit allow-list of trusted origins instead of '*', especially when credentials are allowed.",
    regex: /(?:Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["'])/gi
  },
  {
    id: "node-tls-disabled",
    title: "TLS certificate verification disabled",
    category: "Security misconfiguration",
    severity: "high",
    impact: "rejectUnauthorized:false disables TLS verification, enabling man-in-the-middle attacks.",
    fix: "Remove rejectUnauthorized:false; trust the proper CA chain instead.",
    regex: /rejectUnauthorized\s*:\s*false/g,
    exts: ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
  },
  {
    id: "py-tls-disabled",
    title: "TLS verification disabled (verify=False)",
    category: "Security misconfiguration",
    severity: "high",
    impact: "verify=False disables certificate checking, enabling man-in-the-middle attacks.",
    fix: "Remove verify=False; configure the correct CA bundle if needed.",
    regex: /\bverify\s*=\s*False\b/g,
    exts: ["py"]
  },
  {
    id: "flask-debug-true",
    title: "Debug mode enabled",
    category: "Security misconfiguration",
    severity: "medium",
    impact: "Debug mode exposes an interactive console and stack traces — remote code execution in Flask.",
    fix: "Never run with debug=True / DEBUG=True in production; gate it behind an env flag.",
    regex: /(?:debug\s*=\s*True|DEBUG\s*=\s*True)/g,
    exts: ["py"]
  },
  {
    id: "jwt-alg-none",
    title: 'JWT "none" algorithm accepted',
    category: "Broken authentication",
    severity: "high",
    impact: "Accepting alg:none lets an attacker forge unsigned tokens.",
    fix: "Pin the verification algorithm (e.g. HS256/RS256) and reject 'none'.",
    regex: /["']?alg["']?\s*[:=]\s*["']none["']/gi
  },
  {
    id: "pickle-loads",
    title: "Insecure deserialization (pickle)",
    category: "Insecure deserialization",
    severity: "high",
    impact: "Unpickling untrusted data executes arbitrary code.",
    fix: "Never unpickle untrusted input; use JSON or a safe schema-validated format.",
    regex: /\bpickle\.loads?\s*\(/g,
    exts: ["py"]
  },
  {
    id: "yaml-unsafe-load",
    title: "Unsafe yaml.load()",
    category: "Insecure deserialization",
    severity: "high",
    impact: "yaml.load without SafeLoader can construct arbitrary Python objects (code execution).",
    fix: "Use yaml.safe_load() (or Loader=SafeLoader).",
    regex: /yaml\.load\s*\((?![^)]*Safe)/g,
    exts: ["py"]
  },
  {
    id: "weak-hash",
    title: "Weak hash function (MD5/SHA1)",
    category: "Cryptography",
    severity: "low",
    impact: "MD5/SHA1 are broken for security use (collisions, fast brute force).",
    fix: "Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.",
    regex: /\b(?:md5|sha1)\s*\(/gi
  }
];
