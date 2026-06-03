# Beltic BFF — deployment & secret provisioning

Phase 5 wiring runbook for the Beltic credentials BFF. Run once per Supabase
project (staging, production). One Beltic org per deployment.

Components:

- `beltic-proxy` — user-facing. Verifies the caller's Supabase JWT, checks the
  `user_credentials` ownership index, then proxies to Beltic with the org
  `X-Api-Key` + `X-On-Behalf-Of-Subject`.
- `beltic-audit-poll` — operator-only. Pulls Beltic's audit stream to keep
  `user_credentials` fresh (Beltic has no webhook delivery). Invoked by pg_cron.

## 1. Apply migrations

```bash
supabase db push      # or: supabase migration up
```

Installs `user_credentials` + `beltic_audit_sync` (20260603000000) and the
pg_cron schedule (20260603100000).

## 2. Edge Function secrets

The functions read `BELTIC_API_KEY`, `BELTIC_API_URL`, `BELTIC_ORG` from the
environment (see `.env.example`). `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY`
are injected by the platform — do **not** set them.

Local (`supabase functions serve`): copy `.env.example` → `.env` and fill in.

Hosted:

```bash
supabase secrets set \
  BELTIC_API_KEY="blt_sk_…" \
  BELTIC_API_URL="https://api.beltic.com" \
  BELTIC_ORG="your-org-slug" \
  --project-ref <project-ref>
```

Rotation: re-run `supabase secrets set BELTIC_API_KEY="…"` with the new key and
redeploy. The old key keeps working at Beltic until you revoke it there, so
rotate Beltic-side _after_ the new key is live here.

## 3. Deploy the functions

```bash
supabase functions deploy beltic-proxy      --project-ref <project-ref>
supabase functions deploy beltic-audit-poll --project-ref <project-ref>
```

`beltic-audit-poll` keeps `verify_jwt` on (default): the service-role key is a
valid JWT, so the cron trigger passes, and the function additionally rejects any
caller that isn't the service role.

## 4. Vault secrets for the cron trigger

The pg_cron job (migration 20260603100000) reads the function URL and the
service-role bearer from Vault so neither is hardcoded. Provision both once, in
the SQL editor / `psql`:

```sql
select vault.create_secret(
  'https://<project-ref>.supabase.co/functions/v1/beltic-audit-poll',
  'beltic_audit_poll_url',
  'Beltic audit poller function URL (pg_cron target)'
);

select vault.create_secret(
  '<project service-role key>',
  'beltic_audit_poll_service_key',
  'Service-role bearer the pg_cron job presents to beltic-audit-poll'
);
```

Already provisioned? Update instead of recreate:

```sql
select vault.update_secret(id, '<new value>')
from vault.secrets where name = 'beltic_audit_poll_service_key';
```

Until both secrets exist the cron job runs but no-ops (URL/bearer resolve to
NULL); it begins polling the moment they're set.

## 5. Verify

```sql
-- the job is scheduled
select jobname, schedule, active from cron.job where jobname = 'beltic-audit-poll';

-- recent runs (status + any error)
select status, return_message, start_time
from cron.job_run_details
where jobid = (select jobid from cron.job where jobname = 'beltic-audit-poll')
order by start_time desc limit 5;

-- cursor advancing → poller reaching Beltic and persisting progress
select * from public.beltic_audit_sync order by updated_at desc;
```

A one-off manual poke (service-role key required):

```bash
curl -sS -X POST \
  "https://<project-ref>.supabase.co/functions/v1/beltic-audit-poll" \
  -H "Authorization: Bearer <service-role key>"
```

## Changing the poll cadence

Edit the schedule in `cron.schedule('beltic-audit-poll', '*/2 * * * *', …)` and
re-run migration 20260603100000 (it unschedules the old job first, so it's safe
to re-apply).
