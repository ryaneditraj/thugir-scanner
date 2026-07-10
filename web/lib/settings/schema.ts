// Platform settings — the single source of truth for everything an operator can tune from the
// admin panel. Stored as one JSON document (dev: file, prod: Supabase `platform_settings`).
//
// Secret fields (the per-tier AI apiKey) are stored server-side only and NEVER returned to the
// browser in plaintext — the masked read replaces them with a set/last4 indicator.

export type AiProvider = "openrouter" | "anthropic" | "openai" | "hackclub";
export type TierName = "free" | "deep" | "continuous";

export interface TierAiConfig {
  enabled: boolean;
  provider: AiProvider;
  baseUrl: string; // override the provider endpoint; blank = use the default for `provider`
  model: string;
  apiKey: string; // server-only; masked on read
  temperature: number;
  maxTokens: number;
}

export interface TierAiConfigMasked extends Omit<TierAiConfig, "apiKey"> {
  apiKeySet: boolean;
  apiKeyLast4: string;
}

export interface PlatformSettings {
  general: {
    siteName: string;
    supportEmail: string;
    signupsEnabled: boolean;
    maintenanceMode: boolean;
  };
  scan: {
    freeScanEnabled: boolean;
    requireAttestation: boolean;
    freeMaxScripts: number;
    deepMaxPages: number;
    requestTimeoutMs: number;
  };
  ai: {
    analystEnabled: boolean;
    /** When true, Deep Scan runs an LLM pass over crawled source to find auth/logic issues. */
    deepScanAiEnabled: boolean;
    tiers: Record<TierName, TierAiConfig>;
  };
  security: {
    extraBlockedDomains: string[];
  };
  pricing: Record<TierName, { label: string; price: string; period: string }>;
}

// Client-safe shape: identical except AI keys are masked.
export interface PlatformSettingsMasked extends Omit<PlatformSettings, "ai"> {
  ai: { analystEnabled: boolean; deepScanAiEnabled: boolean; tiers: Record<TierName, TierAiConfigMasked> };
}

const DEFAULT_PROVIDERS: Record<AiProvider, { url: string; defaultModel: string }> = {
  openrouter: { url: "https://openrouter.ai/api/v1/chat/completions", defaultModel: "anthropic/claude-3.5-haiku" },
  anthropic: { url: "https://api.anthropic.com/v1/messages", defaultModel: "claude-3-5-haiku-20241022" },
  openai: { url: "https://api.openai.com/v1/chat/completions", defaultModel: "gpt-4o-mini" },
  hackclub: {
    url: "https://ai.hackclub.com/proxy/v1/chat/completions",
    defaultModel: "qwen/qwen3-32b"
  }
};

export const PROVIDER_ENDPOINTS = DEFAULT_PROVIDERS;
export const AI_PROVIDERS: AiProvider[] = ["hackclub", "openrouter", "anthropic", "openai"];

/** Common models on the Hack Club AI proxy — editable freely in admin settings. */
export const HACKCLUB_MODELS = [
  "qwen/qwen3-32b",
  "moonshotai/kimi-k2",
  "meta-llama/llama-3.3-70b-instruct",
  "google/gemini-2.0-flash-001"
] as const;

function defaultTier(model: string, provider: AiProvider = "hackclub"): TierAiConfig {
  return { enabled: true, provider, baseUrl: "", model, apiKey: "", temperature: 0.2, maxTokens: 900 };
}

export const DEFAULT_SETTINGS: PlatformSettings = {
  general: {
    siteName: "Thugir Scanner",
    supportEmail: "security@thugirlabs.com",
    signupsEnabled: true,
    maintenanceMode: false
  },
  scan: {
    freeScanEnabled: true,
    requireAttestation: true,
    freeMaxScripts: 12,
    deepMaxPages: 25,
    requestTimeoutMs: 8000
  },
  ai: {
    analystEnabled: true,
    deepScanAiEnabled: true,
    tiers: {
      free: { ...defaultTier("qwen/qwen3-32b") },
      deep: { ...defaultTier("qwen/qwen3-32b"), maxTokens: 1500 },
      continuous: { ...defaultTier("qwen/qwen3-32b"), maxTokens: 1500 }
    }
  },
  security: {
    extraBlockedDomains: []
  },
  pricing: {
    free: { label: "Free scan", price: "$0", period: "" },
    deep: { label: "Deep Scan", price: "$29", period: "/ scan" },
    continuous: { label: "Continuous", price: "$99", period: "/ month" }
  }
};

// Deep-merge an incoming partial onto a base, array values replace wholesale.
export function mergeSettings(base: PlatformSettings, patch: DeepPartial<PlatformSettings>): PlatformSettings {
  const out = structuredClone(base);
  const recurse = (target: Record<string, unknown>, src: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(src)) {
      if (v === undefined) continue;
      if (v && typeof v === "object" && !Array.isArray(v)) {
        target[k] = target[k] && typeof target[k] === "object" ? target[k] : {};
        recurse(target[k] as Record<string, unknown>, v as Record<string, unknown>);
      } else {
        target[k] = v;
      }
    }
  };
  recurse(out as unknown as Record<string, unknown>, patch as Record<string, unknown>);
  return out;
}

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export function maskSettings(s: PlatformSettings): PlatformSettingsMasked {
  const maskTier = (t: TierAiConfig): TierAiConfigMasked => {
    const { apiKey, ...rest } = t;
    return { ...rest, apiKeySet: Boolean(apiKey), apiKeyLast4: apiKey ? apiKey.slice(-4) : "" };
  };
  return {
    ...s,
    ai: {
      analystEnabled: s.ai.analystEnabled,
      deepScanAiEnabled: s.ai.deepScanAiEnabled,
      tiers: {
        free: maskTier(s.ai.tiers.free),
        deep: maskTier(s.ai.tiers.deep),
        continuous: maskTier(s.ai.tiers.continuous)
      }
    }
  };
}
