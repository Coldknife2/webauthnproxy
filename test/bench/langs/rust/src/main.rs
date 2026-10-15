use axum::{http::{HeaderMap, HeaderValue, StatusCode}, routing::get, Router};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

// Same algorithm as the application: SHA-256 of the cookie value, lookup in a table of sessions (one entry, seeded at
// start), audience and expiry checks, user lookup.
const TOKEN: &str = "benchAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

struct Sess { user: &'static str, aud: &'static str, exp: u64 }

static TABLE: LazyLock<HashMap<[u8; 32], Sess>> = LazyLock::new(|| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    HashMap::from([(Sha256::digest(TOKEN.as_bytes()).into(), Sess { user: "bench", aud: "app.example.com", exp: now + 86400 })])
});

fn check(h: &HeaderMap) -> Option<String> {
    let host = h.get("x-forwarded-host")?.to_str().ok()?.to_ascii_lowercase();
    if host != "app.example.com" {
        return None;
    }
    let cookie = h.get("cookie")?.to_str().ok()?;
    let tok = cookie.split(';').find_map(|c| c.trim().strip_prefix("wap_session="))?;
    let s = TABLE.get::<[u8; 32]>(&Sha256::digest(tok.as_bytes()).into())?;
    if s.aud != host || s.exp < SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() {
        return None;
    }
    (s.user == "bench").then(|| s.user.to_string()) // user lookup (in-memory set of one)
}

async fn verify(h: HeaderMap) -> (StatusCode, HeaderMap) {
    let mut out = HeaderMap::new();
    match check(&h) {
        Some(u) => {
            out.insert("x-authenticated-user", HeaderValue::from_str(&u).unwrap());
            (StatusCode::OK, out)
        }
        None => (StatusCode::UNAUTHORIZED, out),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/_wap/verify", get(verify));
    let l = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(l, app).await.unwrap();
}
