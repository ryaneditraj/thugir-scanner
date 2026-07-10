"use client";

import { useEffect, useState } from "react";

interface PatternRow {
  id: string;
  slug: string;
  platform: string;
  category: string;
  severity_default: string;
  title: string;
  tier_required: string;
  enabled: boolean;
  version: number;
}

const EMPTY = {
  slug: "",
  platform: "generic",
  category: "",
  severity_default: "medium",
  title: "",
  description: "",
  impact_oneline: "",
  detector_kind: "secret_regex",
  detector_config: "{}",
  tier_required: "free"
};

export default function AdminPatternsPage() {
  const [rows, setRows] = useState<PatternRow[]>([]);
  const [form, setForm] = useState({ ...EMPTY });
  const [msg, setMsg] = useState<string | null>(null);

  async function load() {
    const res = await fetch("/api/admin/patterns");
    const data = await res.json();
    setRows(data.patterns ?? []);
  }
  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setMsg(null);
    let detector_config: unknown = {};
    try {
      detector_config = JSON.parse(form.detector_config || "{}");
    } catch {
      setMsg("detector_config must be valid JSON");
      return;
    }
    const res = await fetch("/api/admin/patterns", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...form, detector_config })
    });
    const data = await res.json();
    if (!res.ok) setMsg(data.error);
    else {
      setMsg("Pattern created.");
      setForm({ ...EMPTY });
      load();
    }
  }

  async function toggle(p: PatternRow) {
    await fetch(`/api/admin/patterns/${p.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !p.enabled })
    });
    load();
  }

  return (
    <article>
      <h1 style={{ fontFamily: "var(--display)" }}>Pattern library</h1>
      <p className="muted">Add or edit AI-builder vulnerability patterns without a redeploy.</p>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ marginTop: 0 }}>New pattern</h3>
        <form onSubmit={create} className="form-grid">
          {(["slug", "platform", "category", "title", "impact_oneline"] as const).map((k) => (
            <input
              key={k}
              placeholder={k}
              value={(form as any)[k]}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })}
            />
          ))}
          <select
            value={form.severity_default}
            onChange={(e) => setForm({ ...form, severity_default: e.target.value })}
          >
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <select
            value={form.detector_kind}
            onChange={(e) => setForm({ ...form, detector_kind: e.target.value })}
          >
            {["secret_regex", "http_probe", "rule_ref"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <select
            value={form.tier_required}
            onChange={(e) => setForm({ ...form, tier_required: e.target.value })}
          >
            {["free", "deep", "continuous"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <textarea
            placeholder="detector_config (JSON)"
            value={form.detector_config}
            onChange={(e) => setForm({ ...form, detector_config: e.target.value })}
            style={{ gridColumn: "1 / -1", fontFamily: "var(--mono)", minHeight: 80 }}
          />
          <button className="btn btn-primary" type="submit" style={{ gridColumn: "1 / -1" }}>
            Create pattern
          </button>
        </form>
        {msg && <p className={`notice${msg.includes("created") ? " ok" : ""}`} style={{ marginTop: 12 }}>{msg}</p>}
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Slug</th>
            <th>Platform</th>
            <th>Severity</th>
            <th>Tier</th>
            <th>Ver</th>
            <th>Enabled</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p) => (
            <tr key={p.id}>
              <td>{p.slug}</td>
              <td>{p.platform}</td>
              <td>{p.severity_default}</td>
              <td>{p.tier_required}</td>
              <td>{p.version}</td>
              <td>{p.enabled ? "yes" : "no"}</td>
              <td>
                <button className="btn btn-secondary" type="button" onClick={() => toggle(p)}>
                  {p.enabled ? "disable" : "enable"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}
