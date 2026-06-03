-- Beltic credentials ownership index + audit poller bookkeeping.
--
-- Phase 5 of the Beltic rollout. Houston owns end-user auth (Supabase Auth);
-- Beltic is the org-scoped, X-Api-Key source of truth for credentials. The
-- `beltic-proxy` Edge Function is a BFF that authenticates the end user, checks
-- the ownership index below ("does this user own credential X?"), and proxies
-- live to Beltic with the org key + an X-On-Behalf-Of-Subject header. We do NOT
-- mirror credential contents here — Beltic stays the source of truth so
-- revocation is always correct. We only keep a thin ownership index so the BFF
-- can authorize a request before proxying.
--
-- The index is kept fresh by polling Beltic `GET /v1/audit/events?since=<cursor>`
-- (Beltic has no webhook delivery). `beltic_audit_sync` holds the last-seen
-- cursor per org/environment so the poller is resumable and idempotent.

-- ---------------------------------------------------------------------------
-- user_credentials: which Houston user owns which Beltic credential.
-- ---------------------------------------------------------------------------
create table if not exists public.user_credentials (
  user_id        uuid        not null references auth.users on delete cascade,
  credential_id  text        not null,
  beltic_org     text        not null,
  environment    text        not null check (environment in ('staging', 'production')),
  -- 'active' once we've seen a credential.issued event; 'revoked' once we've
  -- seen credential.revoked. We keep revoked rows (rather than deleting) so the
  -- BFF can distinguish "you never owned this" (404/403) from "you owned this
  -- but it was revoked" — and so the poller is idempotent on replay.
  status         text        not null default 'active'
                               check (status in ('active', 'revoked')),
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  -- A credential id is unique within an org+environment; the same id could in
  -- principle recur across environments, so all three form the key.
  primary key (credential_id, beltic_org, environment)
);

-- Fast lookup of "all credentials owned by this user" for the list endpoint
-- and the RLS check.
create index if not exists user_credentials_user_id_idx
  on public.user_credentials (user_id);

alter table public.user_credentials enable row level security;

-- A user may read only their own ownership rows. There is deliberately no
-- insert/update/delete policy: only the poller (running with the service role,
-- which bypasses RLS) writes this table. The end-user-facing path is read-only.
create policy "read own credential ownership"
  on public.user_credentials
  for select
  using (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- beltic_audit_sync: poller cursor bookkeeping, one row per org+environment.
-- ---------------------------------------------------------------------------
create table if not exists public.beltic_audit_sync (
  beltic_org     text        not null,
  environment    text        not null check (environment in ('staging', 'production')),
  -- Opaque cursor returned by Beltic's audit feed; passed back as `?since=`.
  -- Null before the first successful poll (full backfill from the start).
  last_cursor    text,
  last_synced_at timestamptz,
  created_at     timestamptz not null default now(),
  primary key (beltic_org, environment)
);

-- No RLS policy + RLS not enabled: this is operator-only bookkeeping touched
-- exclusively by the poller via the service role. It is never read by end
-- users and is not exposed through the user-facing BFF.
alter table public.beltic_audit_sync enable row level security;

comment on table public.user_credentials is
  'Thin ownership index mapping Houston users to Beltic credential ids. Authorizes the beltic-proxy BFF before it proxies live to Beltic. Not a credential mirror.';
comment on table public.beltic_audit_sync is
  'Per-org/env cursor for the Beltic audit-event poller that keeps user_credentials fresh. Operator-only.';
