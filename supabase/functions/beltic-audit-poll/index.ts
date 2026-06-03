// beltic-audit-poll — scheduled poller that keeps the ownership index fresh.
//
// Beltic has no webhook delivery, so Houston pulls. This function polls
// `GET /v1/audit/events?since=<cursor>` for each configured environment,
// upserts `user_credentials` from credential.issued / credential.revoked
// events, and advances the per-org/env cursor. The heavy lifting lives in
// `../_shared/audit_sync.ts` (unit-tested independently).
//
// SCHEDULING (wiring follow-up, not done here): run this on a cron via Supabase
// scheduled functions, e.g. in `supabase/config.toml`:
//
//   [functions.beltic-audit-poll]
//   schedule = "*/2 * * * *"   # every 2 minutes
//
// or via pg_cron + pg_net calling the function URL with the service-role key.
// Either way the trigger must present the service-role bearer so RLS-bypassing
// writes to `user_credentials` succeed.
//
// AUTH: this is an operator endpoint, NOT user-facing. It must be invoked with
// the service-role key (the scheduler holds it). We reject any caller that is
// not the service role to avoid a public trigger of org-wide polling.

import { serviceClient } from "../_shared/auth.ts";
import { type BelticEnvironment, loadBelticConfig } from "../_shared/beltic.ts";
import { jsonError } from "../_shared/http.ts";
import { syncAuditEvents, type SyncResult } from "../_shared/audit_sync.ts";

/** Which environments to poll each run. */
const ENVIRONMENTS: BelticEnvironment[] = ["staging", "production"];

/** True when the caller presented the service-role key as a bearer token. */
function isServiceRoleCaller(req: Request): boolean {
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!serviceKey) return false;
  const auth = req.headers.get("Authorization");
  return auth === `Bearer ${serviceKey}`;
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (!isServiceRoleCaller(req)) {
    return jsonError(401, "Unauthorized");
  }

  let config;
  try {
    config = loadBelticConfig();
  } catch (e) {
    return jsonError(500, `Server misconfigured: ${(e as Error).message}`);
  }

  const db = serviceClient();
  const results: SyncResult[] = [];

  try {
    for (const environment of ENVIRONMENTS) {
      results.push(await syncAuditEvents(db, config, environment));
    }
  } catch (e) {
    // Surface the failure with whatever partial progress we made. The cursor
    // is advanced page-by-page, so a re-run resumes where this left off.
    return jsonError(502, `Audit poll failed: ${(e as Error).message}`);
  }

  return new Response(JSON.stringify({ ok: true, results }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
});
