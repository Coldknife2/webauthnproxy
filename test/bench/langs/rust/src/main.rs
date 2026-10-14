use axum::{http::{HeaderMap, HeaderValue, StatusCode}, routing::get, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &[u8] = b"bench-secret-0123456789abcdef0123456789";

fn check(h: &HeaderMap) -> Option<String> {
    let host = h.get("x-forwarded-host")?.to_str().ok()?.to_ascii_lowercase();
    if host != "app.example.com" {
        return None;
    }
    let cookie = h.get("cookie")?.to_str().ok()?;
    let tok = cookie.split(';').find_map(|c| c.trim().strip_prefix("wap_session="))?;
    let (payload, sig) = tok.rsplit_once('.')?;
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).ok()?;
    mac.update(b"s|");
    mac.update(payload.as_bytes());
    mac.verify_slice(&B64.decode(sig).ok()?).ok()?; // constant-time
    let mut p = payload.split('.');
    let (user, aud, exp, _gen, _seen) = (p.next()?, p.next()?, p.next()?, p.next()?, p.next()?);
    if p.next().is_some() || exp.parse::<u64>().ok()? < SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() {
        return None;
    }
    if String::from_utf8(B64.decode(aud).ok()?).ok()? != host {
        return None;
    }
    let user = String::from_utf8(B64.decode(user).ok()?).ok()?;
    (user == "bench").then_some(user) // user lookup (in-memory set of one)
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
