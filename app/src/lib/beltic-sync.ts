// Pushes Beltic forwarder config to the engine on sign-in + token refresh.
//
// The engine's `/v1/beltic` forwarder needs the Supabase URL, the anon key, and
// the user's (auto-refreshing) access token to reach `beltic-proxy` on the
// user's behalf. The engine is spawned once and can't refresh the token itself,
// so the frontend — which already holds the live, auto-refreshing session —
// pushes it via `PUT /v1/beltic-config` on every relevant auth change, and
// re-pushes after an engine restart (the fresh engine's in-memory config is
// empty again).

import { getEngineConfig, onEngineRestarted, whenEngineReady } from "./engine";
import { logger } from "./logger";
import {
  getSupabasePublicConfig,
  isAuthConfigured,
  supabase,
} from "./supabase";

async function pushBelticConfig(accessToken: string): Promise<void> {
  await whenEngineReady();
  const engine = getEngineConfig();
  if (!engine) return; // not bootstrapped (shouldn't happen after whenEngineReady)
  const { url, anonKey } = getSupabasePublicConfig();
  try {
    const res = await fetch(`${engine.baseUrl}/v1/beltic-config`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${engine.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        supabase_url: url,
        anon_key: anonKey,
        access_token: accessToken,
      }),
    });
    if (!res.ok) {
      // Background sync, not a user-initiated action — log loudly rather than
      // toast. A failure means the agent can't fetch the user's Beltic
      // credentials until the next refresh re-pushes.
      logger.error(`[beltic] engine config push failed: HTTP ${res.status}`);
    }
  } catch (e) {
    logger.error(`[beltic] engine config push error: ${e}`);
  }
}

/**
 * Wire Supabase auth → engine Beltic config. Returns an unsubscribe fn.
 * No-op when auth isn't configured (dev without SUPABASE_URL).
 */
export function startBelticEngineSync(): () => void {
  if (!isAuthConfigured()) return () => {};

  // Push on sign-in, token refresh, and the initial restored session.
  const { data } = supabase.auth.onAuthStateChange((event, session) => {
    const token = session?.access_token;
    if (!token) return;
    if (
      event === "SIGNED_IN" ||
      event === "TOKEN_REFRESHED" ||
      event === "INITIAL_SESSION"
    ) {
      void pushBelticConfig(token);
    }
  });

  // Re-push after an engine restart — the supervisor brings up a fresh engine
  // whose in-memory Beltic config is empty again.
  const offRestart = onEngineRestarted(() => {
    void supabase.auth.getSession().then(({ data: s }) => {
      const token = s.session?.access_token;
      if (token) void pushBelticConfig(token);
    });
  });

  return () => {
    data.subscription.unsubscribe();
    offRestart();
  };
}
