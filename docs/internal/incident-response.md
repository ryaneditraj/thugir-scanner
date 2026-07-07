# Incident response notes

## If a scan job leaks data (we exposed a customer's secret somewhere we shouldn't have)

1. Contain: kill any in-flight scans for the affected target (`/admin/scans`). Disable the
   pattern if a specific check caused over-collection.
2. Assess: evidence is meant to be redacted (`sampleRedacted`, no full secret stored). Query
   `findings.evidence_json` for the affected scan to confirm what was stored.
3. Purge: delete the offending `findings` rows (service role). Note: `admin_audit_log` is
   append-only and must NOT be altered.
4. Notify the customer with what was collected and confirm rotation of any exposed secret.
5. Post-mortem: add a regression (redaction test) so the same field cannot leak again.

## If the admin panel is compromised

1. Revoke all admin sessions (rotate the Supabase JWT secret / sign out all users).
2. Rotate every provider key in `api_keys` immediately (assume all are burned).
3. Rotate `SUPABASE_SERVICE_ROLE_KEY`, `RAZORPAY_*`, `QSTASH_*`, `WORKER_CALLBACK_SECRET`.
4. Set affected `admin_users.disabled = true` and re-enroll MFA for legitimate admins.
5. Review `admin_audit_log` for the blast radius (it is append-only, so it is trustworthy).
6. Force a worker redeploy with new keys; the old keys stop working immediately.

## If the worker is wedged / abused

- Cap breaches: the runner enforces `DEEP_MAX_RUNTIME_S` and endpoint caps. If a job hangs,
  setting `scans.status='killed'` aborts it cooperatively; otherwise restart the worker dyno.

## Secrets hygiene

- The service-role key lives ONLY in Vercel server env + the worker host - never in the client
  bundle (we sell the opposite). `NEXT_PUBLIC_*` is for the anon key only.
