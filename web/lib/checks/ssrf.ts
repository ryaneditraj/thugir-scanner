// Hostname and IP classification for the scan SSRF guard.
// A host is blocked when ANY common parser would treat it as loopback, private,
// link-local, or metadata. Leading-zero IPv4 octets are ambiguous (decimal vs octal);
// if either reading is non-public, the host is blocked.

const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog"
]);

const BLOCKED_SUFFIXES = [".localhost", ".local", ".localdomain", ".internal"];

function stripHost(raw: string): string {
  let host = raw.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.endsWith(".")) host = host.slice(0, -1);
  return host;
}

function interpretations(token: string): number[] {
  if (/^0x[0-9a-f]+$/i.test(token)) {
    const n = Number.parseInt(token, 16);
    return Number.isFinite(n) ? [n] : [];
  }
  if (!/^[0-9]+$/.test(token)) return [];
  const decimal = Number.parseInt(token, 10);
  if (!Number.isFinite(decimal)) return [];
  // "0177" is 127 in octal and 177 in decimal. "08" is not valid octal.
  if (/^0[0-7]+$/.test(token)) {
    const octal = Number.parseInt(token, 8);
    return octal === decimal ? [decimal] : [octal, decimal];
  }
  return [decimal];
}

function combine(parts: number[], lengths: number[]): number | null {
  if (parts.length !== lengths.length) return null;
  let value = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    const bits = lengths[i]!;
    const max = bits === 32 ? 0x1_0000_0000 : 1 << bits;
    if (part < 0 || part >= max) return null;
    value = (value << bits) | part;
  }
  return value >>> 0;
}

/** Every IPv4 address this literal might mean, including short and ambiguous forms. */
export function ipv4Interpretations(host: string): number[] {
  if (host.includes(":")) return [];
  const tokens = host.split(".");
  if (tokens.length < 1 || tokens.length > 4) return [];
  const choices = tokens.map(interpretations);
  if (choices.some((c) => c.length === 0)) return [];

  const widths =
    tokens.length === 1
      ? [32]
      : tokens.length === 2
        ? [8, 24]
        : tokens.length === 3
          ? [8, 8, 16]
          : [8, 8, 8, 8];

  const out: number[] = [];
  const walk = (index: number, acc: number[]) => {
    if (index === choices.length) {
      const combined = combine(acc, widths);
      if (combined !== null) out.push(combined);
      return;
    }
    for (const n of choices[index]!) walk(index + 1, [...acc, n]);
  };
  walk(0, []);
  return out;
}

export function isNonPublicIPv4(value: number): boolean {
  const a = (value >>> 24) & 255;
  const b = (value >>> 16) & 255;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && ((value >>> 8) & 255) === 0) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (value === 0xffffffff) return true;
  return false;
}

function isBlockedIPv6(host: string): boolean {
  const mapped = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mapped) {
    return ipv4Interpretations(mapped[1]!).some(isNonPublicIPv4);
  }
  const mappedHex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (mappedHex) {
    const value = ((Number.parseInt(mappedHex[1]!, 16) << 16) | Number.parseInt(mappedHex[2]!, 16)) >>> 0;
    return isNonPublicIPv4(value);
  }
  if (host === "::1" || host === "::" || host === "0:0:0:0:0:0:0:1") return true;
  // Unique local fc00::/7 and link-local fe80::/10.
  if (/^f[cd][0-9a-f]{0,2}:/i.test(host)) return true;
  if (/^fe[89ab][0-9a-f]:/i.test(host)) return true;
  return false;
}

/** True when this hostname must never be fetched by the scanner. */
export function isBlockedHostname(raw: string): boolean {
  const host = stripHost(raw);
  if (!host) return true;
  if (host === "localhost" || METADATA_HOSTS.has(host)) return true;
  if (BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;
  if (host.includes(":")) return isBlockedIPv6(host);
  const v4 = ipv4Interpretations(host);
  if (v4.length > 0) return v4.some(isNonPublicIPv4);
  // Single-label names ("localhost", "intranet") are not public web origins.
  if (!host.includes(".")) return true;
  return false;
}

/** True when a resolved address (from DNS or a literal) is non-public. */
export function isBlockedIpAddress(address: string): boolean {
  const host = stripHost(address);
  if (host.includes(":")) return isBlockedIPv6(host);
  const v4 = ipv4Interpretations(host);
  if (v4.length === 0) return true;
  return v4.some(isNonPublicIPv4);
}
