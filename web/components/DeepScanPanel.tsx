"use client";

import { useState } from "react";

export default function DeepScanPanel({ currentTier }: { currentTier: string }) {
  const [url, setUrl] = useState("");
  const [domain, setDomain] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [methods, setMethods] = useState<any>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function getToken() {
    setBusy(true);
    setStatus(null);
    try {
      const res = await fetch(`/api/ownership/verify?domain=${encodeURIComponent(url || domain)}`);
      const data = await res.json();
      if (!res.ok) setStatus(data.error);
      else {
        setToken(data.token);
        setMethods(data.methods);
        setDomain(data.domain);
      }
    } finally {
      setBusy(false);
    }
  }

  async function verify(method: string) {
    setBusy(true);
    setStatus(null);
    try {
      const res = await fetch("/api/ownership/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, method })
      });
      const data = await res.json();
      setStatus(data.verified ? "Domain verified." : `Not verified: ${data.detail}`);
    } finally {
      setBusy(false);
    }
  }

  async function runDeep() {
    setBusy(true);
    setStatus(null);
    try {
      const res = await fetch("/api/scan/deep", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      if (!res.ok) {
        if (data.error === "domain_not_verified") setStatus("Verify the domain first (below).");
        else if (data.error === "no_deep_credit") setStatus("You need a Deep Scan credit.");
        else setStatus(data.error);
      } else {
        setStatus(`Deep Scan queued (id ${data.scanId}).`);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ marginTop: 20 }}>
      <h2 style={{ marginTop: 0, fontFamily: "var(--display)" }}>Run a Deep Scan</h2>
      <p className="muted">
        Deep Scan crawls your app, runs the full pattern library, and unlocks all findings. It
        requires verified domain ownership.
      </p>
      <div className="scan-box">
        <input
          type="url"
          placeholder="https://your-app.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button className="btn" disabled={busy} onClick={runDeep}>
          {currentTier === "free" ? "Deep Scan (needs credit)" : "Run Deep Scan"}
        </button>
        <button className="btn secondary" disabled={busy} onClick={getToken}>
          Verify domain
        </button>
      </div>

      {token && methods && (
        <div className="notice" style={{ marginTop: 14 }}>
          <p>
            To verify <b>{domain}</b>, use any one method, then click the matching Verify button:
          </p>
          <ul>
            <li>
              <b>File:</b> create <code>{methods.well_known.path}</code> containing{" "}
              <code>{methods.well_known.content}</code>{" "}
              <button className="btn secondary" disabled={busy} onClick={() => verify("well_known")}>
                Verify file
              </button>
            </li>
            <li>
              <b>Meta tag:</b> add <code>{methods.meta_tag.tag}</code> to your homepage{" "}
              <button className="btn secondary" disabled={busy} onClick={() => verify("meta_tag")}>
                Verify tag
              </button>
            </li>
            <li>
              <b>DNS TXT:</b> add <code>{methods.dns_txt.value}</code>{" "}
              <button className="btn secondary" disabled={busy} onClick={() => verify("dns_txt")}>
                Verify DNS
              </button>
            </li>
          </ul>
        </div>
      )}

      {status && <p className="notice" style={{ marginTop: 12 }}>{status}</p>}
    </div>
  );
}
