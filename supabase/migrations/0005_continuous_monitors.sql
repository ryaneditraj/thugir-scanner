-- Continuous Protection: monitored targets for scheduled re-scans.
create table if not exists monitors (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  target_url text not null,
  enabled boolean not null default true,
  interval_hours int not null default 24 check (interval_hours between 1 and 168),
  last_scan_id uuid references scans (id) on delete set null,
  last_run_at timestamptz,
  next_run_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (user_id, target_url)
);
create index if not exists monitors_due_idx on monitors (enabled, next_run_at);

alter table monitors enable row level security;

create policy monitors_owner_all on monitors
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
