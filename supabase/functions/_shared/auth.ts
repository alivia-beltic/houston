// Shared end-user authentication for the Houston BFF Edge Functions.
//
// The caller is a signed-in Houston desktop user. Their Supabase session JWT
// arrives in the `Authorization: Bearer <jwt>` header. We verify it against
// Supabase Auth using the anon-key client (which validates the JWT signature
// and expiry server-side via getUser) and return the authenticated user id.

import {
  createClient,
  type SupabaseClient,
  type User,
} from "@supabase/supabase-js";

/** Read the Supabase project URL + anon key from the function environment. */
function clientEnv(): { url: string; anonKey: string } {
  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!url || !anonKey) {
    throw new Error("Missing SUPABASE_URL / SUPABASE_ANON_KEY");
  }
  return { url, anonKey };
}

/**
 * A Supabase client bound to the service role, used by the proxy to read the
 * ownership index. Service role bypasses RLS — we do our own ownership check
 * explicitly against the authenticated user id, so we are not relying on RLS
 * here (RLS remains the guard for any direct PostgREST client access).
 */
export function serviceClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) {
    throw new Error("Missing SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY");
  }
  return createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

/**
 * Verify the caller's Supabase session JWT and return the authenticated user.
 * Returns null when the header is missing/malformed or the token is invalid —
 * the caller turns that into a 401.
 */
export async function authenticateUser(req: Request): Promise<User | null> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const { url, anonKey } = clientEnv();
  // Bind the client to the caller's JWT so getUser validates *their* token.
  const client = createClient(url, anonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data, error } = await client.auth.getUser();
  if (error || !data.user) return null;
  return data.user;
}
