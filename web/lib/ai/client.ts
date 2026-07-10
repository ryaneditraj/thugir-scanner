import { PROVIDER_ENDPOINTS, type AiProvider } from "../settings/schema";

export interface AiCallArgs {
  url: string;
  apiKey: string;
  model: string;
  temperature: number;
  maxTokens: number;
  system: string;
  user: string;
  signal: AbortSignal;
}

export async function callAiProvider(provider: AiProvider, a: AiCallArgs): Promise<string | null> {
  if (provider === "anthropic") {
    const res = await fetch(a.url, {
      method: "POST",
      signal: a.signal,
      headers: { "x-api-key": a.apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json" },
      body: JSON.stringify({
        model: a.model,
        max_tokens: a.maxTokens,
        temperature: a.temperature,
        system: a.system,
        messages: [{ role: "user", content: a.user }]
      })
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.content?.[0]?.text ?? null;
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${a.apiKey}`,
    "Content-Type": "application/json"
  };
  if (provider === "openrouter") {
    headers["HTTP-Referer"] = process.env.NEXT_PUBLIC_SITE_URL || "https://scanner.thugirlabs.com";
    headers["X-Title"] = "Thugir Scanner";
  }
  const res = await fetch(a.url, {
    method: "POST",
    signal: a.signal,
    headers,
    body: JSON.stringify({
      model: a.model,
      temperature: a.temperature,
      max_tokens: a.maxTokens,
      messages: [
        { role: "system", content: a.system },
        { role: "user", content: a.user }
      ]
    })
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data?.choices?.[0]?.message?.content ?? null;
}

export function parseAiJson<T>(s: string): T | null {
  const cleaned = s.replace(/```json/gi, "").replace(/```/g, "").trim();
  const start = cleaned.indexOf("{");
  const arrStart = cleaned.indexOf("[");
  const useArr = arrStart !== -1 && (start === -1 || arrStart < start);
  if (useArr) {
    const end = cleaned.lastIndexOf("]");
    if (end === -1 || end <= arrStart) return null;
    try {
      return JSON.parse(cleaned.slice(arrStart, end + 1)) as T;
    } catch {
      return null;
    }
  }
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(cleaned.slice(start, end + 1)) as T;
  } catch {
    return null;
  }
}

export function envKeyFor(provider: AiProvider): string {
  if (provider === "anthropic") return process.env.ANTHROPIC_API_KEY || "";
  if (provider === "openai") return process.env.OPENAI_API_KEY || "";
  if (provider === "hackclub") return process.env.HACK_CLUB_AI_API_KEY || "";
  return process.env.OPENROUTER_API_KEY || "";
}

export function tierAiConfig(
  provider: AiProvider,
  cfg: { model?: string; baseUrl?: string; apiKey?: string; temperature?: number; maxTokens?: number }
) {
  const model = cfg.model || PROVIDER_ENDPOINTS[provider].defaultModel;
  const url = cfg.baseUrl?.trim() || PROVIDER_ENDPOINTS[provider].url;
  return { provider, model, url };
}
