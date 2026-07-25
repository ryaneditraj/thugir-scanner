import { promises as fs } from "fs";
import path from "path";
import {
  DEFAULT_SETTINGS,
  mergeSettings,
  maskSettings,
  AI_PROVIDERS,
  PROVIDER_ENDPOINTS,
  type PlatformSettings,
  type PlatformSettingsMasked,
  type DeepPartial,
  type TierName,
  type AiProvider
} from "./schema";
import { IS_DEV_MODE } from "../devmode";

// Dev/local: a JSON document on disk (Vercel's fs is read-only, so prod uses Supabase).
const DEV_FILE = path.join(process.cwd(), ".data", "platform-settings.json");
const SINGLETON_ID = "singleton";

let memoryCache: PlatformSettings | null = null;

/** Coerce unknown/retired AI providers to openrouter so saved settings stay valid. */
function normalizeSettings(s: PlatformSettings): PlatformSettings {
  const out = structuredClone(s);
  for (const tier of Object.keys(out.ai.tiers) as TierName[]) {
    const t = out.ai.tiers[tier];
    if (!AI_PROVIDERS.includes(t.provider as AiProvider)) {
      t.provider = "openrouter";
      t.baseUrl = "";
      t.model = PROVIDER_ENDPOINTS.openrouter.defaultModel;
    }
  }
  return out;
}

async function readDevFile(): Promise<PlatformSettings> {
  try {
    const raw = await fs.readFile(DEV_FILE, "utf8");
    return normalizeSettings(mergeSettings(DEFAULT_SETTINGS, JSON.parse(raw) as DeepPartial<PlatformSettings>));
  } catch {
    return structuredClone(DEFAULT_SETTINGS);
  }
}

async function writeDevFile(s: PlatformSettings): Promise<void> {
  await fs.mkdir(path.dirname(DEV_FILE), { recursive: true });
  await fs.writeFile(DEV_FILE, JSON.stringify(s, null, 2), "utf8");
}

async function readSupabase(): Promise<PlatformSettings> {
  const { getServiceSupabase } = await import("../supabase/server");
  const svc = getServiceSupabase();
  const { data } = await svc.from("platform_settings").select("data").eq("id", SINGLETON_ID).single();
  if (data?.data) return normalizeSettings(mergeSettings(DEFAULT_SETTINGS, data.data as DeepPartial<PlatformSettings>));
  return structuredClone(DEFAULT_SETTINGS);
}

async function writeSupabase(s: PlatformSettings): Promise<void> {
  const { getServiceSupabase } = await import("../supabase/server");
  const svc = getServiceSupabase();
  await svc
    .from("platform_settings")
    .upsert({ id: SINGLETON_ID, data: s, updated_at: new Date().toISOString() });
}

// Full settings WITH secrets. Server-only. Never send the result to the client unmasked.
export async function loadSettings(): Promise<PlatformSettings> {
  if (memoryCache) return memoryCache;
  memoryCache = IS_DEV_MODE ? await readDevFile() : await readSupabase();
  return memoryCache;
}

export async function loadMaskedSettings(): Promise<PlatformSettingsMasked> {
  return maskSettings(await loadSettings());
}

// Apply a partial update. For each per-tier AI key, an empty string means "leave unchanged"
// (so the masked form can round-trip without ever seeing the secret). Owner-gated upstream.
export async function applyPatch(patch: DeepPartial<PlatformSettings>): Promise<PlatformSettingsMasked> {
  const current = await loadSettings();

  if (patch.ai?.tiers) {
    for (const tier of Object.keys(patch.ai.tiers) as TierName[]) {
      const t = patch.ai.tiers[tier];
      if (t && typeof t.apiKey === "string" && t.apiKey.trim() === "") {
        delete (t as { apiKey?: string }).apiKey; // preserve existing secret
      }
    }
  }

  const next = mergeSettings(current, patch);
  if (IS_DEV_MODE) await writeDevFile(next);
  else await writeSupabase(next);
  memoryCache = next;
  return maskSettings(next);
}

export function invalidateSettingsCache(): void {
  memoryCache = null;
}
