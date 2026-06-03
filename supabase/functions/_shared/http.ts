// Shared HTTP helpers for the Houston BFF Edge Functions.

/**
 * CORS headers. The Houston desktop app calls these functions from a Tauri
 * webview (origin `tauri://localhost` on macOS, `https://tauri.localhost` on
 * Windows) and the mobile PWA from its tunnel origin, so we allow any origin
 * but only the headers/methods we actually use. No credentials cookie is used —
 * auth is a bearer token — so `*` is safe here.
 */
export const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-environment",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

/** JSON error response with CORS headers. */
export function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

/** Preflight response. */
export function handlePreflight(req: Request): Response | null {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  return null;
}
