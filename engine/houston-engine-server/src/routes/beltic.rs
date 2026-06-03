//! `/v1/beltic/*` — thin authenticated forwarder to the Supabase `beltic-proxy`
//! Edge Function.
//!
//! Security model: this engine route is a DUMB PIPE. It does NOT hold the
//! Beltic org key and does NOT do ownership checks — `beltic-proxy` (running in
//! Supabase, with the org key + the `user_credentials` index) stays the only
//! authz boundary. The engine just attaches the end user's Supabase bearer +
//! the project anon key and forwards. The agent (Claude CLI) calls this during
//! a session; the engine bearer (`require_bearer`) already gates who can reach
//! it, so we never re-verify the Supabase JWT here (beltic-proxy does that).
//!
//! Config (supabase_url, anon_key, the user's access_token) is runtime state:
//! the desktop frontend pushes it via `PUT /v1/beltic-config` on sign-in and on
//! every Supabase token refresh. The engine is spawned once with a static env,
//! so a spawn-time token would go stale within the hour — the runtime push is
//! what keeps it fresh. Env seeding (`ServerConfig::beltic_seed`) is only a
//! headless (Always-On / Teams) fallback.

use crate::routes::error::ApiError;
use crate::state::ServerState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
    routing::{get, put},
    Json, Router,
};
use houston_engine_core::CoreError;
use serde::Deserialize;
use std::sync::Arc;

/// Runtime Beltic config the forwarder needs. Held in `ServerState` behind a
/// lock so the frontend can refresh `access_token` mid-session.
#[derive(Debug, Clone)]
pub struct BelticRuntime {
    pub supabase_url: String,
    pub anon_key: String,
    pub access_token: String,
}

impl BelticRuntime {
    /// Seed from env at boot — only when ALL three are present (a partial
    /// config would forward to nowhere or unauthenticated). This is the
    /// headless (Always-On / Teams) fallback; desktop leaves these unset and
    /// the frontend configures the forwarder via `PUT /v1/beltic-config`.
    pub fn from_env() -> Option<Self> {
        let read = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
        Some(Self {
            supabase_url: read("HOUSTON_SUPABASE_URL")?
                .trim_end_matches('/')
                .to_string(),
            anon_key: read("HOUSTON_SUPABASE_ANON_KEY")?,
            access_token: read("HOUSTON_USER_SUPABASE_ACCESS_TOKEN")?,
        })
    }
}

pub fn router() -> Router<Arc<ServerState>> {
    Router::new()
        // PUT /v1/beltic-config — frontend pushes config + refreshed token.
        // Distinct static path (not under `/beltic/`) so it never collides with
        // the catch-all forwarder below.
        .route("/beltic-config", put(set_config))
        // GET|POST /v1/beltic/<path> — forwarded to beltic-proxy/<path>.
        .route("/beltic/*path", get(forward).post(forward))
}

#[derive(Deserialize)]
struct SetConfigBody {
    supabase_url: String,
    anon_key: String,
    access_token: String,
}

/// Frontend pushes Supabase config + the current (or refreshed) access token.
async fn set_config(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<SetConfigBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.supabase_url.trim().is_empty()
        || body.anon_key.trim().is_empty()
        || body.access_token.trim().is_empty()
    {
        return Err(CoreError::BadRequest(
            "supabase_url, anon_key, and access_token are all required".into(),
        )
        .into());
    }
    // Validate the host before we'll ever send the user's Supabase bearer +
    // anon key to it. Without this, anyone who can reach this endpoint could
    // repoint the forwarder at an attacker host and harvest the live token (a
    // credential-exfil / SSRF primitive). Pin https + a Supabase project host.
    if !is_valid_supabase_url(body.supabase_url.trim()) {
        return Err(CoreError::BadRequest(
            "supabase_url must be an https://<project>.supabase.co URL".into(),
        )
        .into());
    }
    let mut guard = state.beltic.write().await;
    *guard = Some(BelticRuntime {
        supabase_url: body.supabase_url.trim_end_matches('/').to_string(),
        anon_key: body.anon_key,
        access_token: body.access_token,
    });
    Ok(Json(serde_json::json!({ "configured": true })))
}

/// True only for an `https://<host>.supabase.co[:port]` URL with NO userinfo.
/// Pins the scheme (no plaintext token over http) and the Supabase project host
/// so the forwarder can't be repointed at an arbitrary host to exfil the user's
/// bearer. Parses with a real RFC-3986 parser (reqwest's `url`) and reads the
/// resolved host — a hand-rolled string split is defeated by userinfo tricks
/// like `https://x.supabase.co:443@evil.com` (real host = evil.com). Pure —
/// unit-tested incl. those bypasses.
fn is_valid_supabase_url(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if parsed.scheme() != "https" {
        return false;
    }
    // Reject any userinfo: `https://<anything>@host` means the real host is
    // after the '@', so a `.supabase.co` substring before it is meaningless.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    match parsed.host_str() {
        // host_str excludes userinfo + port and is lowercased for https. Strip a
        // trailing FQDN dot so `x.supabase.co.` still matches.
        Some(h) => h
            .strip_suffix('.')
            .unwrap_or(h)
            .to_ascii_lowercase()
            .ends_with(".supabase.co"),
        None => false,
    }
}

/// Build the beltic-proxy target URL. Pure — unit-tested.
fn build_target_url(supabase_url: &str, path: &str, query: Option<&str>) -> String {
    let base = supabase_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let mut url = format!("{base}/functions/v1/beltic-proxy/{path}");
    if let Some(q) = query {
        if !q.is_empty() {
            url.push('?');
            url.push_str(q);
        }
    }
    url
}

/// Forward `/v1/beltic/<path>` → `<supabase>/functions/v1/beltic-proxy/<path>`,
/// attaching the user's Supabase bearer + the project anon key.
async fn forward(
    State(state): State<Arc<ServerState>>,
    method: Method,
    Path(path): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    // Clone the config out and drop the lock before any network await.
    let cfg = {
        let guard = state.beltic.read().await;
        guard.clone()
    }
    .ok_or_else(|| {
        CoreError::Unavailable("Beltic is not configured (sign in to Houston)".into())
    })?;

    // Reject dot-segments so a crafted path can't climb out of /beltic-proxy/
    // (defense-in-depth; axum normalizes most, and the host is pinned anyway).
    if path.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(CoreError::BadRequest("invalid path".into()).into());
    }

    let target = build_target_url(&cfg.supabase_url, &path, query.as_deref());

    let client = reqwest::Client::new();
    let mut rb = client
        .request(method, &target)
        .header("Authorization", format!("Bearer {}", cfg.access_token))
        .header("apikey", cfg.anon_key);

    // Pass through only the env selector + content type. Notably we do NOT
    // forward the engine bearer — beltic-proxy authenticates with the Supabase
    // JWT we just set, not Houston's engine token.
    if let Some(env) = headers.get("x-environment") {
        rb = rb.header("X-Environment", env);
    }
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        rb = rb.header(header::CONTENT_TYPE, ct);
    }
    if !body.is_empty() {
        rb = rb.body(body);
    }

    let upstream = rb
        .send()
        .await
        .map_err(|e| CoreError::Unavailable(format!("beltic-proxy unreachable: {e}")))?;

    // Relay status + content-type + body verbatim.
    let status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    // Preserve the evidence-download filename hint if upstream set one. Read
    // headers BEFORE .bytes() consumes the response.
    let content_disposition = upstream
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = upstream
        .bytes()
        .await
        .map_err(|e| CoreError::Unavailable(format!("beltic-proxy read failed: {e}")))?;

    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/json")),
    );
    if let Some(cd) = content_disposition {
        if let Ok(v) = HeaderValue::from_str(&cd) {
            resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
        }
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::{build_target_url, is_valid_supabase_url};

    #[test]
    fn accepts_supabase_project_urls() {
        assert!(is_valid_supabase_url("https://abc.supabase.co"));
        assert!(is_valid_supabase_url("https://abc.supabase.co/"));
        assert!(is_valid_supabase_url("https://abc.supabase.co:443/x"));
    }

    #[test]
    fn rejects_non_supabase_or_insecure_urls() {
        assert!(!is_valid_supabase_url("http://abc.supabase.co")); // not https
        assert!(!is_valid_supabase_url("https://evil.com")); // wrong host
        assert!(!is_valid_supabase_url("https://abc.supabase.co.evil.com")); // suffix trick
        assert!(!is_valid_supabase_url("https://evilsupabase.co")); // no dot boundary
        assert!(!is_valid_supabase_url("https://attacker.com/abc.supabase.co")); // path trick
        assert!(!is_valid_supabase_url("ftp://abc.supabase.co"));
        assert!(!is_valid_supabase_url(""));
    }

    #[test]
    fn rejects_userinfo_exfil_bypasses() {
        // Real host is evil.com in all of these — the old string-split was
        // defeated by the `:443@` form. Reject every userinfo variant.
        assert!(!is_valid_supabase_url("https://abc.supabase.co:443@evil.com"));
        assert!(!is_valid_supabase_url("https://abc.supabase.co@evil.com"));
        assert!(!is_valid_supabase_url("https://user:pass@evil.com"));
        // Even userinfo that itself looks like evil but host is real supabase:
        // reject (legit supabase URLs never carry userinfo).
        assert!(!is_valid_supabase_url("https://evil.com@abc.supabase.co"));
    }

    #[test]
    fn accepts_uppercase_and_trailing_dot_host() {
        // url crate lowercases the host; trailing FQDN dot is stripped.
        assert!(is_valid_supabase_url("https://ABC.SUPABASE.CO"));
        assert!(is_valid_supabase_url("https://abc.supabase.co./x"));
    }

    #[test]
    fn builds_target_with_path_and_query() {
        assert_eq!(
            build_target_url("https://x.supabase.co", "credentials", Some("id=c1&id=c2")),
            "https://x.supabase.co/functions/v1/beltic-proxy/credentials?id=c1&id=c2"
        );
    }

    #[test]
    fn strips_trailing_base_and_leading_path_slashes() {
        assert_eq!(
            build_target_url("https://x.supabase.co/", "/credentials/c1", None),
            "https://x.supabase.co/functions/v1/beltic-proxy/credentials/c1"
        );
    }

    #[test]
    fn ignores_empty_query() {
        assert_eq!(
            build_target_url(
                "https://x.supabase.co",
                "evidence/e1/download",
                Some("")
            ),
            "https://x.supabase.co/functions/v1/beltic-proxy/evidence/e1/download"
        );
    }
}
