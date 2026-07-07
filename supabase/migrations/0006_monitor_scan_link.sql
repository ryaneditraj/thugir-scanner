-- Link scheduled monitor runs to scans + track delta notification.
alter table scans
  add column if not exists monitor_id uuid references monitors (id) on delete set null;

create index if not exists scans_monitor_idx on scans (monitor_id) where monitor_id is not null;

alter table monitors
  add column if not exists delta_notified_at timestamptz;
