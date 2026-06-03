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
