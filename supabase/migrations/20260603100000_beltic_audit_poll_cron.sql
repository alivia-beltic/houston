-- Schedule the Beltic audit poller (Phase 5 wiring).
--
-- Beltic has no webhook delivery, so Houston pulls. This installs a pg_cron job
-- that invokes the `beltic-audit-poll` Edge Function on a fixed interval. The
-- function refreshes the `user_credentials` ownership index from Beltic's audit
-- stream and advances the per-org/env cursor (resumable + idempotent), so the
-- exact cadence is not load-bearing — a missed tick is caught up on the next.
--
-- The job calls the function over HTTP via pg_net, presenting the project
-- service-role key as the bearer (the poller rejects any non-service-role
-- caller). The function URL and service-role key are read from Vault rather
-- than hardcoded, so no secret lands in this migration or in git. The operator
-- provisions those two Vault secrets once per environment — see
-- supabase/functions/BELTIC_BFF_SETUP.md.
--
-- Until the Vault secrets exist the scheduled job still runs but the URL/bearer
-- resolve to NULL and the HTTP call no-ops (logged in cron.job_run_details);
-- it starts working the moment the secrets are set. Scheduling never fails.

create extension if not exists pg_cron with schema extensions;
create extension if not exists pg_net  with schema extensions;

-- Idempotent: drop any prior schedule of the same name before (re)creating it,
-- so re-running this migration (or a later cadence change) doesn't duplicate.
select cron.unschedule('beltic-audit-poll')
where exists (select 1 from cron.job where jobname = 'beltic-audit-poll');

select cron.schedule(
  'beltic-audit-poll',
  '*/2 * * * *', -- every 2 minutes
  $cron$
  select net.http_post(
    url := (
      select decrypted_secret from vault.decrypted_secrets
      where name = 'beltic_audit_poll_url'
    ),
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer ' || (
        select decrypted_secret from vault.decrypted_secrets
        where name = 'beltic_audit_poll_service_key'
      )
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 30000
  );
  $cron$
);
