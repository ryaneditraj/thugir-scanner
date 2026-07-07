"use client";

import { useEffect, useState } from "react";

type Monitor = {
  id: string;
  target_url: string;
  enabled: boolean;
  interval_hours: number;
  last_run_at: string | null;
  next_run_at: string;
};

export default function MonitorsPanel() {
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function load() {
    const res = await fetch("/api/monitors");
    if (!res.ok) return;
    const data = await res.json();
    setMonitors(data.monitors ?? []);
  }

  useEffect(() => {
    load();
  }, []);

  async function addMonitor(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const res = await fetch("/api/monitors", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      if (!res.ok) {
        setErr(data.hint || data.error || "Could not add monitor");
      } else {
        setMsg(`Monitoring ${data.monitor?.target_url ?? url}`);
        setUrl("");
        await load();
      }
    } catch {
      setErr("Network error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="dash-history">
      <h2>Continuous monitors</h2>
      <p className="muted">
        Scheduled Deep Scans on your targets. You get an email when new issues appear or resolve.
      </p>
      <form className="scan-box" onSubmit={addMonitor} style={{ marginTop: 14 }}>
        <div className="scan-field">
          <span className="proto" aria-hidden="true">
            ⌕
          </span>
          <input
            type="text"
            inputMode="url"
            spellCheck={false}
            autoCapitalize="off"
            placeholder="yourapp.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />
        </div>
        <button className="btn btn-primary" type="submit" disabled={busy}>
          {busy ? "Adding…" : "Add monitor"}
        </button>
      </form>
      {err && (
        <p className="notice" style={{ marginTop: 12 }}>
          {err}
        </p>
      )}
      {msg && (
        <p className="dim" style={{ marginTop: 12 }}>
          {msg}
        </p>
      )}
      {monitors.length === 0 ? (
        <p className="muted" style={{ marginTop: 14 }}>
          No monitors yet.
        </p>
      ) : (
        <div className="table-wrap" style={{ marginTop: 16 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Interval</th>
                <th>Last run</th>
                <th>Next run</th>
              </tr>
            </thead>
            <tbody>
              {monitors.map((m) => (
                <tr key={m.id}>
                  <td className="mono-cell">{m.target_url}</td>
                  <td>{m.interval_hours}h</td>
                  <td>{m.last_run_at ? new Date(m.last_run_at).toLocaleString() : "—"}</td>
                  <td>{new Date(m.next_run_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
