//! Signed X25519 application handshake and replay-resistant request guard.

use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use heartlink_sync_protocol::{
    ErrorResponse, HANDSHAKE_PROTOCOL_VERSION, HandshakeRequest, HandshakeResponse,
};
use ring::{
    agreement, digest, hmac, rand as ring_rand,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::{Error as IoError, ErrorKind, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const HANDSHAKE_LIFETIME_SECONDS: i64 = 15 * 60;
const CLOCK_SKEW_SECONDS: i64 = 5 * 60;
const MAX_SIGNED_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_SESSIONS: usize = 4096;
const MAX_NONCES_PER_SESSION: usize = 4096;
const SESSION_HEADER: &str = "x-heartssh-session";
const TIMESTAMP_HEADER: &str = "x-heartssh-timestamp";
const NONCE_HEADER: &str = "x-heartssh-nonce";
const BODY_HASH_HEADER: &str = "x-heartssh-body-sha256";
const SIGNATURE_HEADER: &str = "x-heartssh-signature";

#[derive(Clone)]
struct HandshakeSession {
    key: [u8; 32],
    expires_at: i64,
    nonces: HashSet<String>,
}

#[derive(Clone)]
struct HandshakeInner {
    audience: String,
    key_id: String,
    signing_key: Arc<Ed25519KeyPair>,
    sessions: Arc<Mutex<HashMap<String, HandshakeSession>>>,
}

/// Long-term service identity plus short-lived request-signing sessions.
#[derive(Clone)]
pub struct HandshakeState {
    inner: Arc<HandshakeInner>,
}

impl HandshakeState {
    /// Deterministic development identity used only by in-process tests and examples.
    pub fn development(audience: &str) -> Self {
        let seed = [0x48_u8; 32];
        let Ok(signing_key) = Ed25519KeyPair::from_seed_unchecked(&seed) else {
            panic!("fixed development Ed25519 seed must be valid");
        };
        Self {
            inner: Arc::new(HandshakeInner {
                audience: audience.to_owned(),
                key_id: "development-only".to_owned(),
                signing_key: Arc::new(signing_key),
                sessions: Arc::new(Mutex::new(HashMap::new())),
            }),
        }
    }

    /// Creates a service identity from a Base64URL-encoded 32-byte Ed25519 seed.
    pub fn from_seed_base64(
        audience: impl Into<String>,
        key_id: impl Into<String>,
        seed: &str,
    ) -> Result<Self, IoError> {
        let decoded = URL_SAFE_NO_PAD.decode(seed.trim()).map_err(|_| {
            IoError::new(
                ErrorKind::InvalidInput,
                "handshake private key must be Base64URL without padding",
            )
        })?;
        if decoded.len() != 32 {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "handshake private key must decode to exactly 32 bytes",
            ));
        }
        let signing_key = Ed25519KeyPair::from_seed_unchecked(&decoded).map_err(|_| {
            IoError::new(
                ErrorKind::InvalidInput,
                "handshake private key is not a valid Ed25519 seed",
            )
        })?;
        let audience = audience.into();
        let key_id = key_id.into();
        if !matches!(audience.as_str(), "cloud" | "update") {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "handshake audience must be cloud or update",
            ));
        }
        if key_id.trim().is_empty() || key_id.len() > 64 {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "handshake key id must contain 1 to 64 characters",
            ));
        }
        Ok(Self {
            inner: Arc::new(HandshakeInner {
                audience,
                key_id,
                signing_key: Arc::new(signing_key),
                sessions: Arc::new(Mutex::new(HashMap::new())),
            }),
        })
    }

    /// Reads a Base64URL seed from a server-only file.
    pub fn from_seed_file(
        audience: impl Into<String>,
        key_id: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Self, IoError> {
        let seed = std::fs::read_to_string(path)?;
        Self::from_seed_base64(audience, key_id, &seed)
    }

    /// Generates a new private seed file and returns its public identity key.
    pub fn generate_seed_file(path: impl AsRef<Path>) -> Result<String, IoError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(IoError::new(
                ErrorKind::AlreadyExists,
                "refusing to overwrite an existing handshake key",
            ));
        }
        let rng = ring_rand::SystemRandom::new();
        let mut seed = [0_u8; 32];
        ring_rand::SecureRandom::fill(&rng, &mut seed)
            .map_err(|_| IoError::other("could not generate handshake key"))?;
        let encoded = URL_SAFE_NO_PAD.encode(seed);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;
        let key = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| IoError::other("could not derive handshake public key"))?;
        Ok(URL_SAFE_NO_PAD.encode(key.public_key().as_ref()))
    }

    /// Base64URL-encoded Ed25519 public identity key.
    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.inner.signing_key.public_key().as_ref())
    }

    /// Configured service audience.
    pub fn audience(&self) -> &str {
        &self.inner.audience
    }

    /// Configured signing-key identifier.
    pub fn key_id(&self) -> &str {
        &self.inner.key_id
    }

    /// Signs a canonical payload with the service identity key.
    pub fn sign(&self, payload: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.inner.signing_key.sign(payload).as_ref())
    }
}

/// Public handshake endpoint. It is the only `/v1` route not requiring a session.
pub async fn begin_handshake(
    Extension(state): Extension<HandshakeState>,
    Json(input): Json<HandshakeRequest>,
) -> Result<Json<HandshakeResponse>, HandshakeError> {
    if input.protocol_version != HANDSHAKE_PROTOCOL_VERSION {
        return Err(HandshakeError::Invalid("unsupported handshake protocol"));
    }
    if input.audience != state.inner.audience {
        return Err(HandshakeError::Invalid("handshake audience mismatch"));
    }
    if (input.client_time - now()).abs() > CLOCK_SKEW_SECONDS {
        return Err(HandshakeError::Stale);
    }
    let client_public = decode_bounded(&input.client_public_key, 32, 32)?;
    let client_nonce = decode_bounded(&input.client_nonce, 16, 64)?;
    let rng = ring_rand::SystemRandom::new();
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| HandshakeError::Internal)?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| HandshakeError::Internal)?;
    let peer_public = agreement::UnparsedPublicKey::new(&agreement::X25519, client_public);
    let shared = agreement::agree_ephemeral(private_key, &peer_public, |material| {
        let mut value = [0_u8; 32];
        value.copy_from_slice(material);
        value
    })
    .map_err(|_| HandshakeError::Invalid("invalid X25519 public key"))?;
    let session_id = random_base64(&rng, 32)?;
    let server_nonce = random_base64(&rng, 32)?;
    let server_public_key = URL_SAFE_NO_PAD.encode(public_key.as_ref());
    let client_public_key = input.client_public_key;
    let client_nonce = URL_SAFE_NO_PAD.encode(client_nonce);
    let expires_at = now() + HANDSHAKE_LIFETIME_SECONDS;
    let transcript = handshake_transcript(
        &state.inner.audience,
        &state.inner.key_id,
        &session_id,
        &client_public_key,
        &server_public_key,
        &client_nonce,
        &server_nonce,
        expires_at,
    );
    let session_key = derive_request_key(&shared, transcript.as_bytes());
    {
        let mut sessions = state
            .inner
            .sessions
            .lock()
            .map_err(|_| HandshakeError::Internal)?;
        let timestamp = now();
        sessions.retain(|_, session| session.expires_at > timestamp);
        if sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.expires_at)
                .map(|(id, _)| id.clone())
        {
            sessions.remove(&oldest);
        }
        sessions.insert(
            session_id.clone(),
            HandshakeSession {
                key: session_key,
                expires_at,
                nonces: HashSet::new(),
            },
        );
    }
    Ok(Json(HandshakeResponse {
        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
        audience: state.inner.audience.clone(),
        key_id: state.inner.key_id.clone(),
        session_id,
        server_public_key,
        server_nonce,
        identity_public_key: state.public_key_base64(),
        expires_at,
        signature: state.sign(transcript.as_bytes()),
    }))
}

/// Rejects every protected request which lacks a current signed handshake session.
pub async fn require_handshake(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path();
    if path == "/health" || path == "/v1/handshake" {
        return next.run(request).await;
    }
    match verify_request(request).await {
        Ok(request) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}

async fn verify_request(request: Request<Body>) -> Result<Request<Body>, HandshakeError> {
    let state = request
        .extensions()
        .get::<HandshakeState>()
        .cloned()
        .ok_or(HandshakeError::Internal)?;
    let method = request.method().as_str().to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let headers = request.headers();
    let session_id = header(headers, SESSION_HEADER)?.to_owned();
    let timestamp_text = header(headers, TIMESTAMP_HEADER)?.to_owned();
    let timestamp = timestamp_text
        .parse::<i64>()
        .map_err(|_| HandshakeError::Invalid("invalid request timestamp"))?;
    if (timestamp - now()).abs() > CLOCK_SKEW_SECONDS {
        return Err(HandshakeError::Stale);
    }
    let nonce = header(headers, NONCE_HEADER)?.to_owned();
    decode_bounded(&nonce, 16, 64)?;
    let claimed_body_hash = header(headers, BODY_HASH_HEADER)?.to_owned();
    let signature = URL_SAFE_NO_PAD
        .decode(header(headers, SIGNATURE_HEADER)?)
        .map_err(|_| HandshakeError::Invalid("invalid request signature"))?;
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_SIGNED_BODY_BYTES)
        .await
        .map_err(|_| HandshakeError::Invalid("signed request body is too large"))?;
    let actual_body_hash = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, &bytes));
    if claimed_body_hash != actual_body_hash {
        return Err(HandshakeError::Invalid("request body hash mismatch"));
    }
    let canonical =
        request_signature_payload(&method, &path, &timestamp_text, &nonce, &actual_body_hash);
    {
        let mut sessions = state
            .inner
            .sessions
            .lock()
            .map_err(|_| HandshakeError::Internal)?;
        let current = now();
        sessions.retain(|_, session| session.expires_at > current);
        let session = sessions
            .get_mut(&session_id)
            .ok_or(HandshakeError::Required)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &session.key);
        hmac::verify(&key, canonical.as_bytes(), &signature)
            .map_err(|_| HandshakeError::Invalid("request signature mismatch"))?;
        if !session.nonces.insert(nonce) {
            return Err(HandshakeError::Replay);
        }
        if session.nonces.len() > MAX_NONCES_PER_SESSION {
            sessions.remove(&session_id);
            return Err(HandshakeError::Required);
        }
    }
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

/// Canonical transcript signed by the server identity and reproduced by clients.
#[allow(clippy::too_many_arguments)]
pub fn handshake_transcript(
    audience: &str,
    key_id: &str,
    session_id: &str,
    client_public_key: &str,
    server_public_key: &str,
    client_nonce: &str,
    server_nonce: &str,
    expires_at: i64,
) -> String {
    format!(
        "heartssh-handshake-v1\n{audience}\n{key_id}\n{session_id}\n{client_public_key}\n{server_public_key}\n{client_nonce}\n{server_nonce}\n{expires_at}"
    )
}

fn request_signature_payload(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body_hash: &str,
) -> String {
    format!("{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}")
}

fn derive_request_key(shared: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut material =
        Vec::with_capacity(b"heartssh-request-key-v1\0".len() + transcript.len() + shared.len());
    material.extend_from_slice(b"heartssh-request-key-v1\0");
    material.extend_from_slice(transcript);
    material.push(0);
    material.extend_from_slice(shared);
    let hash = digest::digest(&digest::SHA256, &material);
    let mut key = [0_u8; 32];
    key.copy_from_slice(hash.as_ref());
    key
}

fn decode_bounded(value: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>, HandshakeError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| HandshakeError::Invalid("invalid Base64URL value"))?;
    if decoded.len() < minimum || decoded.len() > maximum {
        return Err(HandshakeError::Invalid(
            "handshake value has invalid length",
        ));
    }
    Ok(decoded)
}

fn random_base64(rng: &ring_rand::SystemRandom, length: usize) -> Result<String, HandshakeError> {
    let mut bytes = vec![0_u8; length];
    ring_rand::SecureRandom::fill(rng, &mut bytes).map_err(|_| HandshakeError::Internal)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn header<'a>(
    headers: &'a axum::http::HeaderMap,
    name: &'static str,
) -> Result<&'a str, HandshakeError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or(HandshakeError::Required)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[derive(Debug)]
/// Failures returned while establishing or validating an application handshake.
pub enum HandshakeError {
    /// No usable handshake session was supplied.
    Required,
    /// A handshake field or signed request field was malformed.
    Invalid(&'static str),
    /// A timestamp was outside the accepted clock-skew window.
    Stale,
    /// A request nonce was used more than once.
    Replay,
    /// The server could not complete a cryptographic operation.
    Internal,
}

impl IntoResponse for HandshakeError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Required => (
                StatusCode::UNAUTHORIZED,
                "handshake_required",
                "complete a signed application handshake before using this endpoint",
            ),
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, "handshake_invalid", message),
            Self::Stale => (
                StatusCode::UNAUTHORIZED,
                "handshake_stale",
                "handshake or request timestamp is outside the accepted window",
            ),
            Self::Replay => (
                StatusCode::UNAUTHORIZED,
                "handshake_replay",
                "request nonce has already been used",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the service could not complete the handshake",
            ),
        };
        (
            status,
            Json(ErrorResponse {
                code: code.to_owned(),
                message: message.to_owned(),
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use heartlink_sync_protocol::{HandshakeRequest, HandshakeResponse};
    use ring::signature;
    use tower::ServiceExt;

    #[tokio::test]
    async fn signed_session_accepts_one_request_and_rejects_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = HandshakeState::development("cloud");
        let service = Router::new()
            .route("/v1/handshake", axum::routing::post(begin_handshake))
            .route("/protected", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(require_handshake))
            .layer(Extension(state.clone()));
        let rng = ring_rand::SystemRandom::new();
        let private = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| IoError::other("client key generation failed"))?;
        let public = private
            .compute_public_key()
            .map_err(|_| IoError::other("client public key failed"))?;
        let client_public = URL_SAFE_NO_PAD.encode(public.as_ref());
        let client_nonce =
            random_base64(&rng, 32).map_err(|_| IoError::other("client nonce failed"))?;
        let body = serde_json::to_vec(&HandshakeRequest {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            audience: "cloud".to_owned(),
            client_public_key: client_public.clone(),
            client_nonce: client_nonce.clone(),
            client_time: now(),
        })?;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/handshake")
            .header("content-type", "application/json")
            .body(Body::from(body))?;
        let response = service.clone().oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let response: HandshakeResponse =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await?)?;
        let transcript = handshake_transcript(
            &response.audience,
            &response.key_id,
            &response.session_id,
            &client_public,
            &response.server_public_key,
            &client_nonce,
            &response.server_nonce,
            response.expires_at,
        );
        let identity = URL_SAFE_NO_PAD.decode(&response.identity_public_key)?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(&response.signature)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, identity)
            .verify(transcript.as_bytes(), &signature_bytes)
            .map_err(|_| IoError::other("server identity signature failed"))?;
        let server_public = URL_SAFE_NO_PAD.decode(&response.server_public_key)?;
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, server_public);
        let shared = agreement::agree_ephemeral(private, &peer, |material| {
            let mut value = [0_u8; 32];
            value.copy_from_slice(material);
            value
        })
        .map_err(|_| IoError::other("client key agreement failed"))?;
        let request_key = derive_request_key(&shared, transcript.as_bytes());
        let timestamp = now().to_string();
        let nonce = random_base64(&rng, 24).map_err(|_| IoError::other("request nonce failed"))?;
        let body_hash = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, b""));
        let canonical =
            request_signature_payload("GET", "/protected", &timestamp, &nonce, &body_hash);
        let key = hmac::Key::new(hmac::HMAC_SHA256, &request_key);
        let request_signature = URL_SAFE_NO_PAD.encode(hmac::sign(&key, canonical.as_bytes()));
        let signed_request = || {
            Request::builder()
                .uri("/protected")
                .header(SESSION_HEADER, &response.session_id)
                .header(TIMESTAMP_HEADER, &timestamp)
                .header(NONCE_HEADER, &nonce)
                .header(BODY_HASH_HEADER, &body_hash)
                .header(SIGNATURE_HEADER, &request_signature)
                .body(Body::empty())
        };
        let accepted = service.clone().oneshot(signed_request()?).await?;
        assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
        let replayed = service.oneshot(signed_request()?).await?;
        assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }
}
