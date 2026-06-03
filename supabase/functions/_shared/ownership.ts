// Ownership-index queries for the Houston BFF.
//
// The proxy authorizes every credential request against `user_credentials`
// before touching Beltic. This is the gate that makes the shared org key safe
// to use on behalf of an individual user.

import type { SupabaseClient } from "@supabase/supabase-js";
import type { BelticEnvironment } from "./beltic.ts";

/** A row of the ownership index relevant to the BFF. */
export interface OwnershipRow {
  credential_id: string;
  status: "active" | "revoked";
}

/**
 * Does this user own this credential in this org+environment? Returns the row
 * if so (including revoked rows, so the caller can distinguish 404 from a
 * revoked credential), or null if the user has no ownership record at all.
 */
export async function findOwnedCredential(
  db: SupabaseClient,
  userId: string,
  org: string,
  environment: BelticEnvironment,
  credentialId: string,
): Promise<OwnershipRow | null> {
  const { data, error } = await db
    .from("user_credentials")
    .select("credential_id, status")
    .eq("user_id", userId)
    .eq("beltic_org", org)
    .eq("environment", environment)
    .eq("credential_id", credentialId)
    .maybeSingle();

  if (error) throw new Error(`ownership lookup failed: ${error.message}`);
  return data as OwnershipRow | null;
}

/**
 * Record proxy-time ownership: the signed-in user just issued this credential
 * through the BFF (on-behalf-of themselves), so they own it. Idempotent upsert
 * keyed on (credential_id, beltic_org, environment) — re-issuing or a retry
 * converges to one active row. This is Houston's ownership SOURCE; the audit
 * poller only flips status to revoked (Beltic's audit feed carries no subject
 * id to attribute ownership on its own).
 */
export async function recordOwnership(
  db: SupabaseClient,
  userId: string,
  org: string,
  environment: BelticEnvironment,
  credentialId: string,
): Promise<void> {
  const { error } = await db.from("user_credentials").upsert(
    {
      user_id: userId,
      credential_id: credentialId,
      beltic_org: org,
      environment,
      status: "active",
      updated_at: new Date().toISOString(),
    },
    { onConflict: "credential_id,beltic_org,environment" },
  );
  if (error) throw new Error(`ownership record failed: ${error.message}`);
}

/**
 * Does `evidenceId` appear in a credential's `evidence_refs`? Owning a
 * credential must NOT grant access to arbitrary evidence ids — the client
 * pairs an evidence id with a credential_id it owns, so the BFF confirms the
 * evidence is actually bound to that credential rather than trusting the
 * pairing (otherwise a user could read another credential's evidence by naming
 * one of their own).
 *
 * Beltic stores refs as `evidence:<id>` (verified against its evidence
 * handlers). We match that exact prefix or a bare `<id>` — deliberately NOT a
 * loose "last colon-segment" match, which could over-match a ref whose tail
 * happens to equal the id (e.g. `sha256:...:ev_x`).
 */
export function evidenceIdInRefs(refs: string[], evidenceId: string): boolean {
  return refs.some((r) => r === evidenceId || r === `evidence:${evidenceId}`);
}

/** All credential ids this user owns in this org+environment (active only). */
export async function listOwnedCredentialIds(
  db: SupabaseClient,
  userId: string,
  org: string,
  environment: BelticEnvironment,
): Promise<string[]> {
  const { data, error } = await db
    .from("user_credentials")
    .select("credential_id")
    .eq("user_id", userId)
    .eq("beltic_org", org)
    .eq("environment", environment)
    .eq("status", "active");

  if (error) throw new Error(`ownership list failed: ${error.message}`);
  return (data ?? []).map((r) =>
    (r as { credential_id: string }).credential_id
  );
}
