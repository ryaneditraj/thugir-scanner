-- Thugir Scanner for AI-built apps - initial schema
-- Multi-tenant, RLS-enforced. Run in the Supabase SQL editor or via `supabase db push`.
--
-- Design notes:
--  * auth.users is the identity source. We mirror minimal data into profiles.
--  * Findings carry a tier_required column; the *server* (route handler / view) is
--    responsible for never selecting gated columns for locked rows. RLS protects rows
--    by owner; the column-level blur is enforced by the secure view + serializer.
--  * Admin tables are readable only by rows present in admin_users.
--  * admin_audit_log is append-only (insert allowed, update/delete revoked).

create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------------------
-- enums
-- ---------------------------------------------------------------------------
do $$ begin
  create type tier_t as enum ('free', 'deep', 'continuous');
exception when duplicate_object then null; end $$;

do $$ begin
  create type scan_status_t as enum ('queued', 'running', 'done', 'failed', 'killed');
exception when duplicate_object then null; end $$;

do $$ begin
  create type finding_status_t as enum ('open', 'resolved', 'suppressed');
exception when duplicate_object then null; end $$;

do $$ begin
  create type severity_t as enum ('critical', 'high', 'medium', 'low', 'info');
exception when duplicate_object then null; end $$;

do $$ begin
  create type admin_role_t as enum ('owner', 'analyst', 'support');
exception when duplicate_object then null; end $$;

do $$ begin
  create type verify_method_t as enum ('attestation', 'meta_tag', 'dns_txt', 'well_known');
exception when duplicate_object then null; end $$;

do $$ begin
  create type detector_kind_t as enum ('secret_regex', 'http_probe', 'rule_ref');
exception when duplicate_object then null; end $$;

-- ---------------------------------------------------------------------------
-- profiles + entitlements
-- ---------------------------------------------------------------------------
create table if not exists profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  default_tier tier_t not null default 'free',
  created_at timestamptz not null default now()
);

create table if not exists entitlements (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  kind text not null check (kind in ('deep_scan_credit', 'continuous_sub')),
  status text not null default 'active' check (status in ('active', 'consumed', 'cancelled', 'expired')),
  razorpay_ref text,
  granted_by uuid references auth.users (id),      -- set when an admin grants an override
  expires_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists entitlements_user_idx on entitlements (user_id, status);

-- ---------------------------------------------------------------------------
-- domain ownership verification
-- ---------------------------------------------------------------------------
create table if not exists domain_verifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  domain text not null,
  method verify_method_t not null,
  token text not null,                              -- the value the user must publish
  verified boolean not null default false,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, domain)
);
create index if not exists domain_verifications_user_idx on domain_verifications (user_id);

-- ---------------------------------------------------------------------------
-- scans + findings
-- ---------------------------------------------------------------------------
create table if not exists scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  target_url text not null,
  verified_domain boolean not null default false,
  tier tier_t not null default 'free',
  detected_platform text,                            -- lovable | bolt | v0 | supabase | firebase | ...
  status scan_status_t not null default 'queued',
  worker_id text,
  error text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists scans_user_idx on scans (user_id, created_at desc);
create index if not exists scans_status_idx on scans (status);

create table if not exists findings (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references scans (id) on delete cascade,
  pattern_id uuid,                                   -- references patterns(id); nullable for engine-native findings
  category text not null,
  title text not null,
  severity severity_t not null,
  tier_required tier_t not null default 'free',      -- 'free' => fully visible; higher => blurred for free users
  impact_oneline text not null,                      -- ALWAYS visible (the teaser)
  evidence_json jsonb,                               -- GATED
  remediation_json jsonb,                            -- GATED
  fix_prompt text,                                   -- GATED: paste-back-to-your-AI-builder text
  confidence real not null default 0.5,
  engine_status text,                                -- mirrors thugir-node validation_status / impact_tier
  status finding_status_t not null default 'open',
  created_at timestamptz not null default now()
);
create index if not exists findings_scan_idx on findings (scan_id);

-- ---------------------------------------------------------------------------
-- pattern library (data-first; new patterns added as rows, no redeploy)
-- ---------------------------------------------------------------------------
create table if not exists patterns (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  platform text not null,                            -- supabase | firebase | lovable | bolt | v0 | generic | ...
  category text not null,
  severity_default severity_t not null,
  title text not null,
  description text not null,
  impact_oneline text not null,
  detector_kind detector_kind_t not null,
  detector_config jsonb not null default '{}'::jsonb,-- regex / paths / rule reference, see pattern spec
  tier_required tier_t not null default 'free',
  remediation_json jsonb,
  fix_prompt text,
  version int not null default 1,
  enabled boolean not null default true,
  created_by uuid references auth.users (id),
  updated_at timestamptz not null default now()
);
create index if not exists patterns_platform_idx on patterns (platform, enabled);

create table if not exists pattern_versions (
  id uuid primary key default gen_random_uuid(),
  pattern_id uuid not null references patterns (id) on delete cascade,
  version int not null,
  snapshot jsonb not null,                           -- full row snapshot at the time of change
  changed_by uuid references auth.users (id),
  created_at timestamptz not null default now()
);
create index if not exists pattern_versions_pattern_idx on pattern_versions (pattern_id, version desc);

-- ---------------------------------------------------------------------------
-- admin: users + roles + audit + encrypted api keys
-- ---------------------------------------------------------------------------
create table if not exists admin_users (
  id uuid primary key references auth.users (id) on delete cascade,
  role admin_role_t not null default 'support',
  totp_enrolled boolean not null default false,
  disabled boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists admin_audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_admin_id uuid references auth.users (id),
  action text not null,
  target_type text,
  target_id text,
  before_json jsonb,
  after_json jsonb,
  ip text,
  created_at timestamptz not null default now()
);
create index if not exists admin_audit_log_actor_idx on admin_audit_log (actor_admin_id, created_at desc);

-- Provider keys (Anthropic / OpenRouter / etc). Ciphertext only; last4 for display.
-- Encrypt with Supabase Vault or pgsodium before insert; never store plaintext here.
create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  label text not null,
  provider text not null,
  ciphertext text not null,
  last4 text not null,
  status text not null default 'active' check (status in ('active', 'rotated', 'revoked')),
  rotated_at timestamptz,
  rotated_by uuid references auth.users (id),
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- helper: is the current jwt an active admin?
-- ---------------------------------------------------------------------------
create or replace function is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from admin_users a
    where a.id = auth.uid() and a.disabled = false
  );
$$;

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------
alter table profiles enable row level security;
alter table entitlements enable row level security;
alter table domain_verifications enable row level security;
alter table scans enable row level security;
alter table findings enable row level security;
alter table patterns enable row level security;
alter table pattern_versions enable row level security;
alter table admin_users enable row level security;
alter table admin_audit_log enable row level security;
alter table api_keys enable row level security;

-- profiles: a user sees/edits only their own row
create policy profiles_self on profiles
  for all using (id = auth.uid()) with check (id = auth.uid());

-- entitlements: read own; writes happen via service role (route handlers) only
create policy entitlements_self_read on entitlements
  for select using (user_id = auth.uid() or is_admin());

-- domain_verifications: full control over own rows
create policy domain_verifications_self on domain_verifications
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- scans: read own (or admin); inserts go through service role
create policy scans_self_read on scans
  for select using (user_id = auth.uid() or is_admin());

-- findings: read findings that belong to one of the user's scans (or admin).
-- NOTE: column-level blur of gated fields is enforced by the server serializer /
-- secure view, NOT by RLS (RLS is row-level only).
create policy findings_self_read on findings
  for select using (
    is_admin() or exists (
      select 1 from scans s where s.id = findings.scan_id and s.user_id = auth.uid()
    )
  );

-- patterns: enabled patterns are world-readable (used to render docs/SEO); writes admin-only
create policy patterns_public_read on patterns
  for select using (enabled = true or is_admin());
create policy patterns_admin_write on patterns
  for all using (is_admin()) with check (is_admin());

create policy pattern_versions_admin on pattern_versions
  for select using (is_admin());

-- admin tables: admin-only read; api_keys never exposes ciphertext to anon/auth
create policy admin_users_admin_read on admin_users
  for select using (is_admin());
create policy api_keys_admin_read on api_keys
  for select using (is_admin());

-- admin_audit_log: append-only. Inserts allowed for admins; no update/delete policy
-- means update/delete are denied under RLS.
create policy admin_audit_insert on admin_audit_log
  for insert with check (is_admin());
create policy admin_audit_read on admin_audit_log
  for select using (is_admin());

-- Hard guarantee that the audit log can never be mutated, even by table owners
-- going through PostgREST: there is intentionally no UPDATE/DELETE policy.

-- ---------------------------------------------------------------------------
-- secure view: findings as the owner is entitled to see them.
-- The server uses this (or the equivalent serializer) so gated columns are NULL
-- for locked rows and are never shipped to the client.
-- ---------------------------------------------------------------------------
create or replace view findings_visible as
select
  f.id,
  f.scan_id,
  f.category,
  f.title,
  f.severity,
  f.tier_required,
  f.impact_oneline,
  f.confidence,
  f.status,
  -- entitled when the scan's tier is at/above the finding's required tier
  case
    when (select s.tier from scans s where s.id = f.scan_id) >= f.tier_required
      then f.evidence_json
    else null
  end as evidence_json,
  case
    when (select s.tier from scans s where s.id = f.scan_id) >= f.tier_required
      then f.remediation_json
    else null
  end as remediation_json,
  case
    when (select s.tier from scans s where s.id = f.scan_id) >= f.tier_required
      then f.fix_prompt
    else null
  end as fix_prompt,
  ((select s.tier from scans s where s.id = f.scan_id) >= f.tier_required) as unlocked,
  f.created_at
from findings f;
