// Shared Beltic client + config for the Houston BFF Edge Functions.
//
// Beltic is an org-scoped, X-Api-Key resource server and the source of truth
// for credentials. The org key is an Edge-Function secret and is NEVER exposed
// to the client. Every proxied call carries the org key as the *actor* and an
// X-On-Behalf-Of-Subject header naming the human *principal* for Beltic's audit
// attribution.

/** Beltic environments. Mirrors the DB check constraint. */
export type BelticEnvironment = "staging" | "production";

export function isBelticEnvironment(v: string): v is BelticEnvironment {
  return v === "staging" || v === "production";
}

/** Required Edge-Function secrets/config, read from the Deno environment. */
export interface BelticConfig {
  /** Org X-Api-Key. Secret. Never returned to the client. */
  apiKey: string;
  /** Base URL of the Beltic API, e.g. https://api.beltic.com. */
  baseUrl: string;
  /** The org slug this deployment is bound to. */
  org: string;
}

/**
 * Read Beltic config from the environment. Throws if a required secret is
 * missing — we want a loud 500 at boot, not a silent fallback that leaks an
 * unauthenticated request to Beltic.
 */
export function loadBelticConfig(): BelticConfig {
  const apiKey = Deno.env.get("BELTIC_API_KEY");
  const baseUrl = Deno.env.get("BELTIC_API_URL");
  const org = Deno.env.get("BELTIC_ORG");

  const missing: string[] = [];
  if (!apiKey) missing.push("BELTIC_API_KEY");
  if (!baseUrl) missing.push("BELTIC_API_URL");
  if (!org) missing.push("BELTIC_ORG");
  if (missing.length > 0) {
    throw new Error(`Missing Beltic config: ${missing.join(", ")}`);
  }

  // Trim a trailing slash so path joins are predictable.
  return { apiKey: apiKey!, baseUrl: baseUrl!.replace(/\/$/, ""), org: org! };
}

/**
 * Perform a GET against Beltic with the org key, environment, and on-behalf-of
 * principal. `path` must start with a leading slash (e.g. `/v1/credentials`).
 *
 * Returns the raw `Response` so callers can stream bodies (evidence downloads)
 * or forward status + JSON verbatim without re-parsing.
 */
export async function belticGet(
  config: BelticConfig,
  environment: BelticEnvironment,
  onBehalfOfSubject: string,
  path: string,
): Promise<Response> {
  const url = `${config.baseUrl}${path}`;
  return await fetch(url, {
    method: "GET",
    headers: {
      "X-Api-Key": config.apiKey,
      "X-Environment": environment,
      "X-On-Behalf-Of-Subject": onBehalfOfSubject,
      "Accept": "application/json",
    },
  });
}

/**
 * POST to Beltic with the org key, environment, and on-behalf-of principal.
 * Used to issue a credential for the end user — the `onBehalfOfSubject` is the
 * Houston user id, so Beltic attributes the issuance to them and the BFF can
 * record proxy-time ownership from the response. Returns the raw `Response`.
 */
export async function belticPost(
  config: BelticConfig,
  environment: BelticEnvironment,
  onBehalfOfSubject: string,
  path: string,
  body: unknown,
): Promise<Response> {
  const url = `${config.baseUrl}${path}`;
  return await fetch(url, {
    method: "POST",
    headers: {
      "X-Api-Key": config.apiKey,
      "X-Environment": environment,
      "X-On-Behalf-Of-Subject": onBehalfOfSubject,
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify(body),
  });
}
