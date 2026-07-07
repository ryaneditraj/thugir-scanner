-- Platform settings: a single JSON document tuned from the admin panel.
-- Holds per-tier AI provider/model/key config, scan limits, pricing, feature flags, etc.
-- Service-role only — never exposed to clients (the admin API masks secrets before returning).

create table if not exists platform_settings (
  id text primary key default 'singleton',
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table platform_settings enable row level security;
-- No policies => only the service role (which bypasses RLS) can read/write. Admin panel uses it.

insert into platform_settings (id, data)
values ('singleton', '{}'::jsonb)
on conflict (id) do nothing;
