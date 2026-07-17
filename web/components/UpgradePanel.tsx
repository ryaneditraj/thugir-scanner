"use client";

import { useState } from "react";

declare global {
  interface Window {
    Razorpay?: new (options: Record<string, unknown>) => { open: () => void };
  }
}

function loadRazorpayScript(): Promise<boolean> {
  return new Promise((resolve) => {
    if (window.Razorpay) {
      resolve(true);
      return;
    }
    const s = document.createElement("script");
    s.src = "https://checkout.razorpay.com/v1/checkout.js";
    s.onload = () => resolve(true);
    s.onerror = () => resolve(false);
    document.body.appendChild(s);
  });
}

export default function UpgradePanel({
  currentTier,
  deepCredits = 0
}: {
  currentTier: string;
  deepCredits?: number;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  if (currentTier === "continuous") return null;

  async function startCheckout(kind: "deep_scan_credit" | "continuous_sub") {
    setBusy(kind);
    setErr(null);
    setOk(null);
    try {
      const res = await fetch("/api/billing/create-order", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind })
      });
      const data = await res.json();
      if (!res.ok) {
        setErr(
          data.error ||
            "Billing unavailable. Set RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, and NEXT_PUBLIC_RAZORPAY_KEY_ID."
        );
        return;
      }

      const loaded = await loadRazorpayScript();
      if (!loaded || !window.Razorpay) {
        setErr("Could not load Razorpay checkout");
        return;
      }

      const options: Record<string, unknown> = {
        key: data.keyId,
        name: "Thugir Scanner",
        description: kind === "continuous_sub" ? "Continuous Protection" : "Deep Scan credit",
        prefill: data.prefill || {},
        theme: { color: "#12667e" },
        handler: async (response: {
          razorpay_order_id?: string;
          razorpay_payment_id: string;
          razorpay_signature: string;
          razorpay_subscription_id?: string;
        }) => {
          const verify = await fetch("/api/billing/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              orderId: response.razorpay_order_id,
              subscriptionId: response.razorpay_subscription_id,
              paymentId: response.razorpay_payment_id,
              signature: response.razorpay_signature,
              kind
            })
          });
          if (verify.ok) {
            setOk("Payment confirmed — your plan is active. Refreshing…");
            setTimeout(() => window.location.reload(), 1200);
          } else {
            const v = await verify.json().catch(() => ({}));
            setErr(v.error || "Payment received but entitlement grant failed — contact support.");
          }
        }
      };

      if (kind === "continuous_sub") {
        options.subscription_id = data.subscriptionId;
      } else {
        options.order_id = data.orderId;
        options.amount = data.amount;
        options.currency = data.currency;
      }

      const rzp = new window.Razorpay(options);
      rzp.open();
    } catch {
      setErr("Network error starting checkout");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="upgrade-panel">
      <div className="upgrade-copy">
        <h2>Unlock full findings</h2>
        <p>
          Free scans show confirmed issues plus sealed teasers. <b>Deep Scan</b> unlocks every
          pattern, full evidence, and paste-back fix prompts. <b>Continuous</b> re-scans on a schedule
          and emails you when things change.
        </p>
        {deepCredits > 0 && (
          <p className="upgrade-credit-note">
            You have <b>{deepCredits}</b> unused Deep Scan credit{deepCredits === 1 ? "" : "s"} —
            run a Deep Scan in the portal below.
          </p>
        )}
      </div>
      <div className="upgrade-actions">
        {currentTier === "free" && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null}
            onClick={() => startCheckout("deep_scan_credit")}
          >
            {busy === "deep_scan_credit" ? "Opening checkout…" : "Buy Deep Scan · from ₹499"}
          </button>
        )}
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy !== null}
          onClick={() => startCheckout("continuous_sub")}
        >
          {busy === "continuous_sub" ? "Opening checkout…" : "Continuous Protection"}
        </button>
      </div>
      {err && <p className="notice">{err}</p>}
      {ok && <p className="notice ok-notice">{ok}</p>}
    </section>
  );
}
