"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Tier } from "@/lib/patterns/types";

// Lets the signed-in admin force their own account to behave as a given customer tier so they can
// see exactly what each tier sees (blur gate, dashboard, reports). Persists server-side.
export default function TierPreview({ initialOverride }: { initialOverride: Tier | null }) {
  const router = useRouter();
  const [value, setValue] = useState<string>(initialOverride ?? "auto");
  const [saving, setSaving] = useState(false);

  async function change(next: string) {
    setValue(next);
    setSaving(true);
    try {
      await fetch("/api/admin/preview-tier", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tier: next })
      });
      router.refresh();
    } finally {
      setSaving(false);
    }
  }

  const active = value !== "auto";
  return (
    <span className={`tierprev${active ? " active" : ""}`}>
      <span className="tierprev-label">Preview as</span>
      <select
        value={value}
        onChange={(e) => change(e.target.value)}
        disabled={saving}
        aria-label="Preview the platform as a customer tier"
      >
        <option value="auto">Auto (your real access)</option>
        <option value="free">Free</option>
        <option value="deep">Deep Scan</option>
        <option value="continuous">Continuous</option>
      </select>
    </span>
  );
}
