-- Admin tier preview overrides.
-- A signed-in admin can force their OWN account to behave as free / deep / continuous so they can
-- experience the platform the way each customer tier does. Only admins ever get a row here (the
-- admin API is the only writer), so honoring an override can never escalate a normal user.

create table if not exists admin_tier_overrides (
  admin_id uuid primary key references auth.users (id) on delete cascade,
  tier text not null check (tier in ('free', 'deep', 'continuous')),
  updated_at timestamptz not null default now()
);

alter table admin_tier_overrides enable row level security;
-- No policies => only the service role (which bypasses RLS) can read/write. Admin panel uses it.
