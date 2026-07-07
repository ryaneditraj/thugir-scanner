# Admin panel runbook

The admin console (`/admin`) is a high-value target: it stores AI-provider keys and
payment-adjacent data. Treat it accordingly.

## Access model

- Normal Supabase Auth session **plus** a row in `admin_users` (roles: `owner` > `analyst` >
  `support`). Both checks are enforced in [admin layout](../../web/app/(admin)/admin/layout.tsx)
  via `getAdminContext`.
- The panel is robots-disallowed ([robots.ts](../../web/app/robots.ts)) and `no-store` +
  `noindex` ([next.config.mjs](../../web/next.config.mjs)). There are no public links to it.
- 2FA is required for all admin accounts (enroll via Supabase MFA; track `totp_enrolled`).
- Login attempts are rate-limited per IP (`checkAdminLoginLimit`).

## Granting admin access

Insert a row into `admin_users` (owner only), then have the user enroll MFA. Example SQL:
```sql
insert into admin_users (id, role, totp_enrolled) values ('<auth.users.id>', 'analyst', false);
```

## Key rotation procedure (API provider keys)

Keys are stored encrypted (Supabase Vault / pgsodium); only `last4` is ever shown; plaintext is
never returned by the API.
1. Generate the new key with the provider.
2. Encrypt it (Vault) and `POST /api/admin/api-keys` with `{provider, ciphertext, last4}` (owner).
3. Mark the old key `rotated`/`revoked`.
4. Confirm services using the key pick up the new value.
5. The action is audited automatically (`api_key.create`).

## Handling abuse reports

1. Find the scan(s) in **Scans** (`/admin/scans`).
2. Kill in-flight jobs with the kill button (`scan.kill`, cooperative cancel).
3. If a user is abusing the free tier, lower their entitlement / suspend (User management) and
   rely on Upstash rate limits.

## Refund / credit process

1. In **Users**, locate the user and their `entitlements`.
2. Issue the refund in the Razorpay dashboard.
3. Set the corresponding `entitlements` row `status='cancelled'` (or grant a credit by inserting a
   `deep_scan_credit` row with `granted_by` = your admin id). Both are audited.

## QA'ing the pattern library

Use **Scan oversight** to view raw findings before users see them, and **Patterns** to disable a
noisy pattern instantly (no redeploy). Every change is versioned in `pattern_versions`.
