# Local dev setup

## Prerequisites
- Node 20+, Python 3.11+, a Supabase project, an Upstash (Redis + QStash) account, Razorpay test keys.

## 1. Supabase
1. Create a project.
2. Run [supabase/migrations/0001_init.sql](../../supabase/migrations/0001_init.sql) in the SQL editor.
3. (Optional) Run [supabase/seed/patterns.sql](../../supabase/seed/patterns.sql) to seed the DB pattern table.
4. Enable Email (magic link) and Google providers under Authentication.

## 2. Web app (Next.js)
```bash
cd web
cp .env.example .env.local   # fill in Supabase + Upstash + Razorpay + WORKER_URL
npm install
npm run dev                  # http://localhost:3000
```
Make yourself an admin:
```sql
insert into admin_users (id, role) values ('<your auth.users.id>', 'owner');
```

## 3. Deep Scan worker (Python)
See [worker/README.md](../../worker/README.md). In dev you can run it with
`ALLOW_UNSIGNED_JOBS=1` and post jobs by hand.

## 4. End-to-end
- Free scan: sign in, tick the attestation, scan a URL you own.
- Deep scan: in the dashboard, verify the domain (file/meta/DNS), then run a Deep Scan (you need a
  `deep_scan_credit` - grant one to yourself via SQL for testing).

## Useful commands
```bash
npm run typecheck   # tsc --noEmit
npm run lint
```

See [environment-variables.md](environment-variables.md) for every variable.
