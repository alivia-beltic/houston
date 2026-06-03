// Audit-event sync logic for the Houston ownership index.
//
// Beltic has no webhook delivery, so Houston keeps `user_credentials` fresh by
// polling `GET /v1/audit/events?since=<cursor>`. We translate
// `credential.issued` / `credential.revoked` events into upserts on the
// ownership index and advance the per-org/env cursor.
//
// This module holds the pure-ish logic (event -> upsert, cursor handling) so it
// can be unit-tested without a live Beltic. The scheduled function
// `beltic-audit-poll` is the thin wiring around `syncAuditEvents`.

import type { SupabaseClient } from "@supabase/supabase-js";
import {
  type BelticConfig,
  type BelticEnvironment,
  belticGet,
} from "./beltic.ts";

/**
 * A single Beltic audit event, narrowed to the fields the poller consumes.
 * Beltic returns more; we ignore the rest.
 */
export interface BelticAuditEvent {
  /** e.g. "credential.issued", "credential.revoked", and others we skip. */
  type: string;
  /** The credential the event concerns. */
  credential_id: string;
  /**
   * The Houston end-user this credential belongs to — Beltic stores the
   * X-On-Behalf-Of-Subject it was issued under as the subject/principal.
   */
  subject: string;
}

/** Beltic's audit feed page shape. */
export interface BelticAuditPage {
  events: BelticAuditEvent[];
  /** Cursor to pass as the next `?since=`. Absent/null when caught up. */
  next_cursor: string | null;
}

/** Result of one sync run, for logging/observability. */
export interface SyncResult {
  org: string;
  environment: BelticEnvironment;
  pagesFetched: number;
  eventsApplied: number;
  finalCursor: string | null;
}

/** Read the stored cursor for an org+environment (null before first poll). */
async function readCursor(
  db: SupabaseClient,
  org: string,
  environment: BelticEnvironment,
): Promise<string | null> {
  const { data, error } = await db
    .from("beltic_audit_sync")
    .select("last_cursor")
    .eq("beltic_org", org)
    .eq("environment", environment)
    .maybeSingle();
  if (error) throw new Error(`cursor read failed: ${error.message}`);
  return (data as { last_cursor: string | null } | null)?.last_cursor ?? null;
}

/** Persist the advanced cursor + sync timestamp. */
async function writeCursor(
  db: SupabaseClient,
  org: string,
  environment: BelticEnvironment,
  cursor: string | null,
): Promise<void> {
  const { error } = await db.from("beltic_audit_sync").upsert(
    {
      beltic_org: org,
      environment,
      last_cursor: cursor,
      last_synced_at: new Date().toISOString(),
    },
    { onConflict: "beltic_org,environment" },
  );
  if (error) throw new Error(`cursor write failed: ${error.message}`);
}

/**
 * Apply one audit event to the ownership index. Idempotent: replaying the same
 * event (e.g. after a crash before the cursor advanced) produces the same
 * state. Unknown event types are ignored.
 */
export async function applyEvent(
  db: SupabaseClient,
  org: string,
  environment: BelticEnvironment,
  event: BelticAuditEvent,
): Promise<boolean> {
  if (event.type === "credential.issued") {
    const { error } = await db.from("user_credentials").upsert(
      {
        user_id: event.subject,
        credential_id: event.credential_id,
        beltic_org: org,
        environment,
        status: "active",
        updated_at: new Date().toISOString(),
      },
      { onConflict: "credential_id,beltic_org,environment" },
    );
    if (error) throw new Error(`issue upsert failed: ${error.message}`);
    return true;
  }

  if (event.type === "credential.revoked") {
    // Mark revoked rather than delete: keeps the BFF able to distinguish
    // "revoked" from "never owned", and keeps replay idempotent.
    const { error } = await db
      .from("user_credentials")
      .update({ status: "revoked", updated_at: new Date().toISOString() })
      .eq("credential_id", event.credential_id)
      .eq("beltic_org", org)
      .eq("environment", environment);
    if (error) throw new Error(`revoke update failed: ${error.message}`);
    return true;
  }

  return false; // unrelated event type — skip
}

/**
 * Poll Beltic's audit feed from the stored cursor, apply every
 * credential.issued/revoked event to the ownership index, and advance the
 * cursor. Drains all pages in one run (bounded by `maxPages` to avoid an
 * unbounded loop on a misbehaving feed).
 */
export async function syncAuditEvents(
  db: SupabaseClient,
  config: BelticConfig,
  environment: BelticEnvironment,
  maxPages = 100,
): Promise<SyncResult> {
  const org = config.org;
  let cursor = await readCursor(db, org, environment);
  let pagesFetched = 0;
  let eventsApplied = 0;

  for (let page = 0; page < maxPages; page++) {
    const qs = cursor ? `?since=${encodeURIComponent(cursor)}` : "";
    const res = await belticGet(
      config,
      environment,
      // The poller acts as the org itself, not a single end user. Beltic's
      // audit feed is org-scoped; the on-behalf-of subject is a system marker.
      "system:houston-audit-poller",
      `/v1/audit/events${qs}`,
    );
    if (!res.ok) {
      throw new Error(`audit feed returned ${res.status}`);
    }
    const body = (await res.json()) as BelticAuditPage;
    pagesFetched++;

    for (const event of body.events ?? []) {
      const applied = await applyEvent(db, org, environment, event);
      if (applied) eventsApplied++;
    }

    // Advance the cursor only after a page's events are durably applied, so a
    // crash mid-page replays that page (idempotently) rather than skipping it.
    if (body.next_cursor) {
      cursor = body.next_cursor;
      await writeCursor(db, org, environment, cursor);
    }

    // Caught up: no further pages.
    if (!body.next_cursor || (body.events ?? []).length === 0) break;
  }

  return { org, environment, pagesFetched, eventsApplied, finalCursor: cursor };
}
