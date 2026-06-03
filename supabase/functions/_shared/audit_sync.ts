// Audit-event sync logic for the Houston ownership index.
//
// Beltic has no webhook delivery, so Houston keeps `user_credentials` fresh by
// polling `GET /v1/audit/events?cursor=<cursor>`. We translate
// `credential.revoked` events into status updates on the ownership index and
// advance the per-org/env cursor.
//
// OWNERSHIP SOURCE — UNRESOLVED (blocks issue-time ownership): Beltic's audit
// feed pseudonymizes the subject — it exposes `subject_type` only, with no
// subject id / human identifier — so this poller CANNOT create ownership rows
// on `credential.issued`. Ownership must be established at proxy time (the BFF
// knows the Houston user from their Supabase JWT and can write the row when the
// user first issues/fetches a credential), OR Beltic must expose the issued-for
// subject in the audit event. Until that decision lands, the issued branch is a
// logged no-op; only `credential.revoked` is applied (it keys on credential_id
// alone, so it needs no subject).
//
// This module holds the pure-ish logic so it can be unit-tested without a live
// Beltic. The scheduled function `beltic-audit-poll` is the thin wiring around
// `syncAuditEvents`.

import type { SupabaseClient } from "@supabase/supabase-js";
import {
  type BelticConfig,
  type BelticEnvironment,
  belticGet,
} from "./beltic.ts";

/**
 * A single Beltic audit event, narrowed to the fields the poller consumes.
 * Field names mirror Beltic's `auditEventResponseSchema` exactly. Beltic
 * returns more fields; we ignore the rest.
 */
export interface BelticAuditEvent {
  /** e.g. "credential.issued", "credential.revoked", and others we skip. */
  event_type: string;
  /** The credential the event concerns. */
  credential_id: string;
  /**
   * Subject category only ("user" | "organisation" | "agent"). Beltic does NOT
   * expose the subject's id in the audit feed (it's pseudonymized), so this
   * cannot be used to map a credential to a Houston user — see the header note.
   */
  subject_type: string;
}

/** Beltic's audit feed page shape (mirrors `auditEventListResponseSchema`). */
export interface BelticAuditPage {
  events: BelticAuditEvent[];
  /** Cursor to pass as the next `?cursor=`. Null when caught up. */
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
  if (event.event_type === "credential.issued") {
    // Cannot create an ownership row here: the audit feed carries no subject id
    // to attribute the credential to a Houston user (see the header note).
    // Ownership is established at proxy time instead. Skip, don't fail.
    console.warn(
      `[audit-sync] credential.issued ${event.credential_id} skipped — ` +
        `no subject id in audit feed; ownership set at proxy time`,
    );
    return false;
  }

  if (event.event_type === "credential.revoked") {
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
    const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
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
