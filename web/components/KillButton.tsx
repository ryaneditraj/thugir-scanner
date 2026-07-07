"use client";

import { useState } from "react";

export default function KillButton({ scanId }: { scanId: string }) {
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  async function kill() {
    setBusy(true);
    await fetch(`/api/admin/scans/${scanId}/kill`, { method: "POST" });
    setDone(true);
    setBusy(false);
  }
  if (done) return <span className="muted">killed</span>;
  return (
    <button className="btn secondary" disabled={busy} onClick={kill}>
      kill
    </button>
  );
}
