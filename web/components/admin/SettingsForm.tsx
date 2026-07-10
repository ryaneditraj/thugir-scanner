"use client";

import { useState } from "react";
import { AI_PROVIDERS, HACKCLUB_MODELS, PROVIDER_ENDPOINTS, type AiProvider, type PlatformSettingsMasked, type TierName } from "@/lib/settings/schema";

const TIERS: TierName[] = ["free", "deep", "continuous"];

export default function SettingsForm({ initial }: { initial: PlatformSettingsMasked }) {
  const [s, setS] = useState<PlatformSettingsMasked>(initial);
  // New AI keys the operator types this session (per tier). Blank = leave existing key untouched.
  const [keyInput, setKeyInput] = useState<Record<TierName, string>>({ free: "", deep: "", continuous: "" });
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState<Record<TierName, boolean>>({ free: false, deep: false, continuous: false });
  const [testMsg, setTestMsg] = useState<Record<TierName, { ok: boolean; text: string } | null>>({ free: null, deep: null, continuous: null });

  // Live-test a tier's AI config using the values currently in the form (so the operator can
  // confirm a key/model/URL works BEFORE saving). Sends the typed key if one was entered.
  async function testTier(t: TierName) {
    const cfg = s.ai.tiers[t];
    setTesting((x) => ({ ...x, [t]: true }));
    setTestMsg((x) => ({ ...x, [t]: null }));
    try {
      const res = await fetch("/api/admin/ai-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tier: t, provider: cfg.provider, model: cfg.model, baseUrl: cfg.baseUrl, apiKey: keyInput[t] })
      });
      const data = await res.json();
      setTestMsg((x) => ({ ...x, [t]: { ok: !!data.ok, text: data.detail ?? data.error ?? (data.ok ? "Connected." : "Test failed.") } }));
    } catch {
      setTestMsg((x) => ({ ...x, [t]: { ok: false, text: "Network error reaching the test endpoint." } }));
    } finally {
      setTesting((x) => ({ ...x, [t]: false }));
    }
  }

  function patchGeneral(p: Partial<PlatformSettingsMasked["general"]>) {
    setS((v) => ({ ...v, general: { ...v.general, ...p } }));
  }
  function patchScan(p: Partial<PlatformSettingsMasked["scan"]>) {
    setS((v) => ({ ...v, scan: { ...v.scan, ...p } }));
  }
  function patchTier(tier: TierName, p: Partial<PlatformSettingsMasked["ai"]["tiers"][TierName]>) {
    setS((v) => ({ ...v, ai: { ...v.ai, tiers: { ...v.ai.tiers, [tier]: { ...v.ai.tiers[tier], ...p } } } }));
  }
  function setTierProvider(tier: TierName, provider: AiProvider) {
    const defaults = PROVIDER_ENDPOINTS[provider];
    patchTier(tier, { provider, baseUrl: "", model: defaults.defaultModel });
  }
  function patchPricing(tier: TierName, p: Partial<PlatformSettingsMasked["pricing"][TierName]>) {
    setS((v) => ({ ...v, pricing: { ...v.pricing, [tier]: { ...v.pricing[tier], ...p } } }));
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMsg(null);
    // Build the patch. AI keys: send typed value, or "" to preserve the stored secret.
    const patch = {
      general: s.general,
      scan: s.scan,
      security: { extraBlockedDomains: s.security.extraBlockedDomains },
      pricing: s.pricing,
      ai: {
        analystEnabled: s.ai.analystEnabled,
        deepScanAiEnabled: s.ai.deepScanAiEnabled ?? true,
        tiers: Object.fromEntries(
          TIERS.map((t) => {
            const { apiKeySet: _set, apiKeyLast4: _l4, ...rest } = s.ai.tiers[t];
            return [t, { ...rest, apiKey: keyInput[t] }];
          })
        )
      }
    };
    try {
      const res = await fetch("/api/admin/settings", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch)
      });
      const data = await res.json();
      if (!res.ok) {
        setMsg({ ok: false, text: data.error ?? "Save failed" });
      } else {
        setS(data.settings);
        setKeyInput({ free: "", deep: "", continuous: "" });
        setMsg({ ok: true, text: "Settings saved." });
      }
    } catch {
      setMsg({ ok: false, text: "Network error" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="aset" onSubmit={save} noValidate>
      {/* GENERAL */}
      <section className="aset-group">
        <h2>General</h2>
        <div className="aset-grid">
          <label className="fld">
            <span>Site name</span>
            <input value={s.general.siteName} onChange={(e) => patchGeneral({ siteName: e.target.value })} />
          </label>
          <label className="fld">
            <span>Support email</span>
            <input type="email" value={s.general.supportEmail} onChange={(e) => patchGeneral({ supportEmail: e.target.value })} />
          </label>
        </div>
        <Toggle label="Allow new signups" checked={s.general.signupsEnabled} onChange={(v) => patchGeneral({ signupsEnabled: v })} />
        <Toggle label="Maintenance mode (disable scanning site-wide)" checked={s.general.maintenanceMode} onChange={(v) => patchGeneral({ maintenanceMode: v })} danger />
      </section>

      {/* SCAN ENGINE */}
      <section className="aset-group">
        <h2>Scan engine</h2>
        <Toggle label="Free scan enabled" checked={s.scan.freeScanEnabled} onChange={(v) => patchScan({ freeScanEnabled: v })} />
        <Toggle label="Require ownership attestation before a scan" checked={s.scan.requireAttestation} onChange={(v) => patchScan({ requireAttestation: v })} />
        <div className="aset-grid">
          <label className="fld">
            <span>Free scan — max scripts examined</span>
            <input type="number" min={1} max={50} step={1} value={s.scan.freeMaxScripts} onChange={(e) => patchScan({ freeMaxScripts: clampInt(e.target.value, 50, s.scan.freeMaxScripts) })} />
          </label>
          <label className="fld">
            <span>Deep scan — max pages crawled</span>
            <input type="number" min={1} max={500} step={1} value={s.scan.deepMaxPages} onChange={(e) => patchScan({ deepMaxPages: clampInt(e.target.value, 500, s.scan.deepMaxPages) })} />
          </label>
          <label className="fld">
            <span>Request timeout (ms)</span>
            <input type="number" min={1000} max={30000} step={100} value={s.scan.requestTimeoutMs} onChange={(e) => patchScan({ requestTimeoutMs: clampInt(e.target.value, 30000, s.scan.requestTimeoutMs) })} />
          </label>
        </div>
      </section>

      {/* AI MODELS — per tier */}
      <section className="aset-group">
        <h2>AI models &amp; keys</h2>
        <p className="aset-note">
          Each tier can use a different provider, model, and API key. Hack Club AI is the default for hackathon demos.
          Change the <b>Model</b> field per tier — saved settings apply immediately to scans. Leave a key blank to keep the stored one or use the env fallback.
        </p>
        <Toggle label="AI analyst layer enabled (master switch)" checked={s.ai.analystEnabled} onChange={(v) => setS((x) => ({ ...x, ai: { ...x.ai, analystEnabled: v } }))} />
        <Toggle label="AI Deep Scan (LLM reads crawled source for auth/logic bugs)" checked={s.ai.deepScanAiEnabled ?? true} onChange={(v) => setS((x) => ({ ...x, ai: { ...x.ai, deepScanAiEnabled: v } }))} />
        {TIERS.map((t) => {
          const cfg = s.ai.tiers[t];
          return (
            <div className="aset-tier" key={t}>
              <div className="aset-tier-head">
                <span className="tier-name">{t}</span>
                <span className="aset-tier-actions">
                  <button type="button" className="btn-mini" onClick={() => testTier(t)} disabled={testing[t]}>
                    {testing[t] ? "Testing…" : "Test AI"}
                  </button>
                  <Toggle label="enabled" checked={cfg.enabled} onChange={(v) => patchTier(t, { enabled: v })} small />
                </span>
              </div>
              {testMsg[t] && (
                <p className={testMsg[t]!.ok ? "aset-test-ok" : "aset-test-err"}>
                  {testMsg[t]!.ok ? "✓ " : "✕ "}
                  {testMsg[t]!.text}
                </p>
              )}
              <div className="aset-grid">
                <label className="fld">
                  <span>Provider</span>
                  <select value={cfg.provider} onChange={(e) => setTierProvider(t, e.target.value as AiProvider)}>
                    {AI_PROVIDERS.map((p) => (
                      <option key={p} value={p}>{p === "hackclub" ? "Hack Club AI" : p}</option>
                    ))}
                  </select>
                </label>
                <label className="fld">
                  <span>API base URL</span>
                  <input value={cfg.baseUrl} onChange={(e) => patchTier(t, { baseUrl: e.target.value })} placeholder={PROVIDER_ENDPOINTS[cfg.provider].url} spellCheck={false} autoCapitalize="off" />
                </label>
                <label className="fld">
                  <span>Model</span>
                  <input
                    value={cfg.model}
                    onChange={(e) => patchTier(t, { model: e.target.value })}
                    placeholder={PROVIDER_ENDPOINTS[cfg.provider].defaultModel}
                    list={cfg.provider === "hackclub" ? `hackclub-models-${t}` : undefined}
                    spellCheck={false}
                    autoCapitalize="off"
                  />
                  {cfg.provider === "hackclub" && (
                    <datalist id={`hackclub-models-${t}`}>
                      {HACKCLUB_MODELS.map((m) => (
                        <option key={m} value={m} />
                      ))}
                    </datalist>
                  )}
                </label>
                <label className="fld">
                  <span>API key {cfg.apiKeySet ? <em className="keyset">set · ••••{cfg.apiKeyLast4}</em> : <em className="keyunset">not set</em>}</span>
                  <input
                    type="password"
                    autoComplete="off"
                    value={keyInput[t]}
                    onChange={(e) => setKeyInput((k) => ({ ...k, [t]: e.target.value }))}
                    placeholder={cfg.apiKeySet ? "Enter a new key to replace" : "Paste API key"}
                  />
                </label>
                <label className="fld">
                  <span>Temperature</span>
                  <input type="number" min={0} max={2} step={0.01} value={cfg.temperature} onChange={(e) => patchTier(t, { temperature: clampFloat(e.target.value, 2, cfg.temperature) })} />
                </label>
                <label className="fld">
                  <span>Max tokens</span>
                  <input type="number" min={64} max={8000} step={1} value={cfg.maxTokens} onChange={(e) => patchTier(t, { maxTokens: clampInt(e.target.value, 8000, cfg.maxTokens) })} />
                </label>
              </div>
            </div>
          );
        })}
      </section>

      {/* SECURITY */}
      <section className="aset-group">
        <h2>Security</h2>
        <label className="fld">
          <span>Additional blocked domains (one per line) — refused on the free scan</span>
          <textarea
            rows={4}
            value={s.security.extraBlockedDomains.join("\n")}
            onChange={(e) => setS((x) => ({ ...x, security: { extraBlockedDomains: e.target.value.split("\n").map((d) => d.trim()).filter(Boolean) } }))}
            placeholder={"example-i-dont-own.com\nanother.com"}
          />
        </label>
      </section>

      {/* PRICING */}
      <section className="aset-group">
        <h2>Pricing (shown on the marketing page)</h2>
        {TIERS.map((t) => (
          <div className="aset-grid" key={t}>
            <label className="fld">
              <span>{t} — label</span>
              <input value={s.pricing[t].label} onChange={(e) => patchPricing(t, { label: e.target.value })} />
            </label>
            <label className="fld">
              <span>{t} — price</span>
              <input value={s.pricing[t].price} onChange={(e) => patchPricing(t, { price: e.target.value })} />
            </label>
            <label className="fld">
              <span>{t} — period</span>
              <input value={s.pricing[t].period} onChange={(e) => patchPricing(t, { period: e.target.value })} placeholder="/ scan" />
            </label>
          </div>
        ))}
      </section>

      <div className="aset-bar">
        <button className="btn btn-primary" type="submit" disabled={saving}>
          {saving ? "Saving…" : "Save all settings"}
        </button>
        {msg && <span className={msg.ok ? "aset-ok" : "aset-err"}>{msg.text}</span>}
      </div>
    </form>
  );
}

// Parse a number input without ever producing NaN (empty / mid-edit keeps the previous value).
// We only cap the upper bound and floor at 0 so typing stays smooth — the lower `min` is left as
// a native hint. step is always 1 (or 0.1 for floats) so default values can never be "off-grid".
function clampInt(raw: string, max: number, fallback: number): number {
  if (raw.trim() === "") return fallback;
  const n = Math.round(Number(raw));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(0, n));
}

function clampFloat(raw: string, max: number, fallback: number): number {
  if (raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(0, Math.round(n * 100) / 100));
}

function Toggle({ label, checked, onChange, small, danger }: { label: string; checked: boolean; onChange: (v: boolean) => void; small?: boolean; danger?: boolean }) {
  return (
    <label className={`tgl${small ? " sm" : ""}${danger ? " danger" : ""}`}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="tgl-track" aria-hidden="true"><span className="tgl-dot" /></span>
      <span className="tgl-label">{label}</span>
    </label>
  );
}
