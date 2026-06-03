// beltic-proxy — Houston's partner BFF for Beltic credentials.
//
// Phase 5 of the Beltic rollout. This Edge Function lets a signed-in Houston
// end user see *their own* Beltic credentials without ever handling the org
// X-Api-Key. The flow per request:
//
//   1. Verify the caller's Supabase session JWT  -> end-user id.
//   2. Check the `user_credentials` ownership index: does this user own the
//      requested credential?  -> 403 if not.
//   3. Proxy live to Beltic with the org X-Api-Key (a function secret),
//      X-Environment, and X-On-Behalf-Of-Subject: <user-id> for audit
//      attribution. Return Beltic's response verbatim.
//
// Live proxy (no mirror) keeps Beltic the source of truth and makes revocation
// correct. The org key is never exposed to the client.
//
// Routes, under the function base path `/beltic-proxy`:
//   POST /credentials                     -> issue a credential FOR the user;
//                                            records proxy-time ownership
//   GET  /credentials                     -> list the user's own credentials
//   GET  /credentials/:id                 -> one credential (ownership-checked)
//   GET  /evidence/:id                    -> evidence metadata (ownership-checked
//                                            against its parent credential)
//   GET  /evidence/:id/download           -> evidence bytes (same check)
//
// Ownership SOURCE is POST /credentials (the user issues on-behalf-of
// themselves, so the BFF knows the user from their JWT and records the row).
// The audit poller only flips status to revoked — Beltic's audit feed carries
// no subject id to attribute ownership.
//
// Environment is selected by the `X-Environment: staging|production` request
// header (default staging).

import { authenticateUser, serviceClient } from "../_shared/auth.ts";
import {
  type BelticEnvironment,
  belticGet,
  belticPost,
  isBelticEnvironment,
  loadBelticConfig,
} from "../_shared/beltic.ts";
import { corsHeaders, handlePreflight, jsonError } from "../_shared/http.ts";
import {
  evidenceIdInRefs,
  findOwnedCredential,
  listOwnedCredentialIds,
  recordOwnership,
} from "../_shared/ownership.ts";

/** Strip the function name prefix so we get the app-level route path. */
function routePath(url: URL): string {
  // Invoked URL looks like `/beltic-proxy/credentials/abc`. Drop the first
  // segment (the function name) to get `/credentials/abc`.
  const parts = url.pathname.split("/").filter((p) => p.length > 0);
  if (parts.length > 0 && parts[0] === "beltic-proxy") parts.shift();
  return "/" + parts.join("/");
}

function resolveEnvironment(req: Request): BelticEnvironment {
  const raw = req.headers.get("X-Environment") ?? "staging";
  return isBelticEnvironment(raw) ? raw : "staging";
}

/** Forward a Beltic Response to the client, preserving status + content type. */
function forward(res: Response): Response {
  const headers = new Headers(corsHeaders);
  const contentType = res.headers.get("Content-Type");
  if (contentType) headers.set("Content-Type", contentType);
  const contentDisposition = res.headers.get("Content-Disposition");
  if (contentDisposition) {
    headers.set("Content-Disposition", contentDisposition);
  }
  return new Response(res.body, { status: res.status, headers });
}

Deno.serve(async (req: Request): Promise<Response> => {
  const preflight = handlePreflight(req);
  if (preflight) return preflight;

  if (req.method !== "GET" && req.method !== "POST") {
    return jsonError(405, "Method not allowed");
  }

  // --- config ------------------------------------------------------------
  let config;
  try {
    config = loadBelticConfig();
  } catch (e) {
    // Misconfiguration -> loud 500. Do not fall through to an unauthenticated
    // upstream call.
    return jsonError(500, `Server misconfigured: ${(e as Error).message}`);
  }

  // --- authenticate the end user ----------------------------------------
  const user = await authenticateUser(req);
  if (!user) return jsonError(401, "Unauthorized");

  const environment = resolveEnvironment(req);
  const db = serviceClient();
  const url = new URL(req.url);
  const path = routePath(url);

  try {
    // --- POST /credentials  (issue for the user; record ownership) ------
    // This is Houston's ownership SOURCE. The user issues a credential through
    // the BFF on-behalf-of themselves; on success we record the (user ->
    // credential) row so subsequent reads + the revoke poller can authorize.
    if (req.method === "POST" && path === "/credentials") {
      const requestBody = await req.json().catch(() => null);
      if (requestBody === null) return jsonError(400, "Invalid JSON body");
      const res = await belticPost(
        config,
        environment,
        user.id,
        "/v1/credentials",
        requestBody,
      );
      const text = await res.text();
      if (res.ok) {
        // Parse the issued credential id and record ownership before returning.
        // If Beltic succeeded but we can't read the id, fail loudly — a silent
        // success would leave the user unable to read what they just issued.
        let credentialId: string | undefined;
        try {
          credentialId = (JSON.parse(text) as { credential_id?: string })
            .credential_id;
        } catch {
          credentialId = undefined;
        }
        if (!credentialId) {
          return jsonError(
            502,
            "Beltic issued a credential but the response had no credential_id; ownership not recorded",
          );
        }
        await recordOwnership(
          db,
          user.id,
          config.org,
          environment,
          credentialId,
        );
      }
      const headers = new Headers(corsHeaders);
      headers.set("Content-Type", "application/json");
      return new Response(text, { status: res.status, headers });
    }

    if (req.method !== "GET") return jsonError(405, "Method not allowed");

    // --- GET /credentials  (list the user's own) ------------------------
    if (path === "/credentials") {
      const ids = await listOwnedCredentialIds(
        db,
        user.id,
        config.org,
        environment,
      );
      if (ids.length === 0) {
        // Nothing owned: return an empty list rather than hitting Beltic with
        // an org-wide list the user isn't entitled to see.
        return new Response(JSON.stringify({ credentials: [] }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      // Ask Beltic only for the ids this user owns. Beltic's list endpoint
      // accepts repeated `id` query params; the proxy never lists the whole
      // org on behalf of one user.
      const qs = ids.map((id) => `id=${encodeURIComponent(id)}`).join("&");
      const res = await belticGet(
        config,
        environment,
        user.id,
        `/v1/credentials?${qs}`,
      );
      return forward(res);
    }

    // --- GET /credentials/:id -------------------------------------------
    const credMatch = path.match(/^\/credentials\/([^/]+)$/);
    if (credMatch) {
      const credentialId = decodeURIComponent(credMatch[1]);
      const owned = await findOwnedCredential(
        db,
        user.id,
        config.org,
        environment,
        credentialId,
      );
      if (!owned) return jsonError(403, "You do not own this credential");
      const res = await belticGet(
        config,
        environment,
        user.id,
        `/v1/credentials/${encodeURIComponent(credentialId)}`,
      );
      return forward(res);
    }

    // --- GET /evidence/:id  and  /evidence/:id/download -----------------
    // Evidence is owned transitively through its parent credential. The client
    // names the parent credential via `?credential_id=`; the BFF then checks
    // (1) the user owns that credential AND (2) the evidence is actually bound
    // to it (in its evidence_refs). Both are required — owning a credential
    // must not grant access to arbitrary evidence ids.
    const evMatch = path.match(/^\/evidence\/([^/]+)(\/download)?$/);
    if (evMatch) {
      const evidenceId = decodeURIComponent(evMatch[1]);
      const isDownload = Boolean(evMatch[2]);
      const credentialId = url.searchParams.get("credential_id");
      if (!credentialId) {
        return jsonError(
          400,
          "credential_id query param is required to authorize evidence access",
        );
      }
      const owned = await findOwnedCredential(
        db,
        user.id,
        config.org,
        environment,
        credentialId,
      );
      if (!owned) {
        return jsonError(
          403,
          "You do not own the credential for this evidence",
        );
      }
      // Owning the credential isn't enough — confirm the evidence is actually
      // bound to it. The client pairs the two; trusting that pairing would let
      // a user read any org evidence by naming a credential they own. Fetch the
      // credential and check its evidence_refs.
      const credRes = await belticGet(
        config,
        environment,
        user.id,
        `/v1/credentials/${encodeURIComponent(credentialId)}`,
      );
      if (!credRes.ok) {
        return jsonError(
          403,
          "You do not own the credential for this evidence",
        );
      }
      const cred = (await credRes.json().catch(() => null)) as
        | { evidence_refs?: string[] }
        | null;
      if (!evidenceIdInRefs(cred?.evidence_refs ?? [], evidenceId)) {
        return jsonError(
          403,
          "This evidence is not part of the named credential",
        );
      }
      const suffix = isDownload ? "/download" : "";
      const res = await belticGet(
        config,
        environment,
        user.id,
        `/v1/evidence/${encodeURIComponent(evidenceId)}${suffix}`,
      );
      return forward(res);
    }

    return jsonError(404, "Not found");
  } catch (e) {
    // Surface the real reason — no silent swallow. The ownership lookup or the
    // upstream fetch failed; the client sees a 502 with the message.
    return jsonError(502, `Beltic proxy error: ${(e as Error).message}`);
  }
});
