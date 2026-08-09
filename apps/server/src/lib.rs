//! HeartLink opaque synchronization service.

pub mod admin;
pub mod handshake;

use crate::handshake::{HandshakeState, begin_handshake, require_handshake};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use heartlink_shared_models::{CipherRecord, RecordKind, RevisionedRecord};
use heartlink_sync_protocol::{
    AcknowledgeDeviceControlRequest, CredentialsRequest, DeviceControlAction, DeviceControlCommand,
    DeviceControlResponse, DeviceResponse, ErrorResponse, HealthResponse, PROTOCOL_VERSION,
    PullResponse, PushRequest, PushResponse, RecoveryAuthorizeUnlockRequest,
    RecoveryChallengeResponse, RecoveryChannel, RecoveryPurpose, RecoveryRequest,
    RecoveryResetPasswordRequest, RecoveryVerifiedResponse, RecoveryVerifyRequest,
    RegisterDeviceRequest, SessionResponse,
};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use rand::{RngCore, rngs::OsRng};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, Row, any::AnyPoolOptions};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

const SESSION_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
const DEFAULT_USER_QUOTA_BYTES: i64 = 64 * 1024 * 1024;
const MAX_REVISIONS_PER_USER: i64 = 100;
const MAX_CONFLICTS_PER_USER: i64 = 20;
const RECOVERY_CODE_LIFETIME_SECONDS: i64 = 10 * 60;
const RECOVERY_TOKEN_LIFETIME_SECONDS: i64 = 10 * 60;
const RECOVERY_RESEND_SECONDS: i64 = 60;
const RECOVERY_MAX_ATTEMPTS: i64 = 5;
const DEVICE_ONLINE_WINDOW_SECONDS: i64 = 90;
const DEVICE_ID_HEADER: &str = "x-heartlink-device-id";
const DEVICE_CONTROL_HEADER: &str = "x-heartlink-device-control";
const ALIYUN_SMS_HOST: &str = "dysmsapi.aliyuncs.com";
const IDCN_ACCOUNT_ENDPOINT: &str = "https://www.idcnetwork.cn/console/v1/account";
const IDCN_LOGIN_ENDPOINT: &str = "https://www.idcnetwork.cn/console/v1/login";
const IDCN_EXTERNAL_PROVIDER: &str = "idcn";
const MAX_EXTERNAL_TOKEN_BYTES: usize = 16 * 1024;

/// Cloneable service dependencies.
#[derive(Clone)]
pub struct AppState {
    pool: AnyPool,
    database_kind: DatabaseKind,
    registration_enabled: bool,
    recovery_pepper: String,
    recovery_delivery: RecoveryDelivery,
    settings_key: Option<Arc<[u8; 32]>>,
    handshake: HandshakeState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseKind {
    Sqlite,
    MySql,
}

/// Runtime configuration which does not contain secrets.
#[derive(Clone)]
pub struct ServerConfig {
    /// Whether public account registration is accepted.
    pub registration_enabled: bool,
    /// Server-only secret mixed into hashes of low-entropy verification codes.
    pub recovery_pepper: String,
    /// Email/SMS delivery backend.
    pub recovery_delivery: RecoveryDelivery,
    /// Optional key for provider secrets configured by the private admin UI.
    pub settings_key: Option<[u8; 32]>,
    /// Signed application-handshake identity.
    pub handshake: HandshakeState,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            registration_enabled: true,
            recovery_pepper: "development-only-change-this-recovery-pepper".to_owned(),
            recovery_delivery: RecoveryDelivery::Disabled,
            settings_key: None,
            handshake: HandshakeState::development("cloud"),
        }
    }
}

/// Verification-code delivery backend.
#[derive(Clone, Debug)]
pub enum RecoveryDelivery {
    /// Recovery endpoints return a configuration error and never expose codes.
    Disabled,
    /// POST recovery messages to provider-owned HTTPS gateways.
    Webhook {
        /// Email delivery webhook.
        email_url: Option<String>,
        /// SMS delivery webhook.
        sms_url: Option<String>,
        /// Optional bearer token shared with both webhooks.
        bearer_token: Option<String>,
    },
    /// In-memory delivery sink used by end-to-end recovery tests.
    #[cfg(test)]
    Capture(std::sync::Arc<std::sync::Mutex<Vec<RecoveryMessage>>>),
}

/// Payload delivered to a mail/SMS gateway.
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryMessage {
    /// Delivery channel.
    pub channel: RecoveryChannel,
    /// Registered destination.
    pub destination: String,
    /// Six-digit code.
    pub code: String,
    /// Reset purpose.
    pub purpose: RecoveryPurpose,
    /// Code lifetime.
    pub expires_in_seconds: i64,
}

/// Initializes the configured database and applies embedded migrations.
pub async fn initialize(database_url: &str) -> Result<AppState, sqlx::Error> {
    initialize_with_config(database_url, ServerConfig::default()).await
}

/// Initializes SQLite or MySQL using explicit service configuration.
pub async fn initialize_with_config(
    database_url: &str,
    config: ServerConfig,
) -> Result<AppState, sqlx::Error> {
    sqlx::any::install_default_drivers();
    let database_kind = if database_url.starts_with("mysql://") {
        DatabaseKind::MySql
    } else if database_url.starts_with("sqlite:") {
        DatabaseKind::Sqlite
    } else {
        return Err(sqlx::Error::Configuration(
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HEARTLINK_DATABASE_URL must use mysql:// or sqlite:",
            )
            .into(),
        ));
    };
    let max_connections = if database_url == "sqlite::memory:" {
        1
    } else {
        10
    };
    let pool = AnyPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await?;
    match database_kind {
        DatabaseKind::Sqlite => sqlx::migrate!().run(&pool).await?,
        DatabaseKind::MySql => sqlx::migrate!("./migrations_mysql").run(&pool).await?,
    }
    Ok(AppState {
        pool,
        database_kind,
        registration_enabled: config.registration_enabled,
        recovery_pepper: config.recovery_pepper,
        recovery_delivery: config.recovery_delivery,
        settings_key: config.settings_key.map(Arc::new),
        handshake: config.handshake,
    })
}

/// Builds the HTTP application. Vault plaintext types do not appear in this boundary.
pub fn app(state: AppState) -> Router {
    build_app(state, true)
}

fn build_app(state: AppState, protect_routes: bool) -> Router {
    let handshake = state.handshake.clone();
    let router = Router::new()
        .route("/health", get(health))
        .route("/v1/handshake", post(begin_handshake))
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/external/idcn", post(authenticate_idcn))
        .route(
            "/v1/auth/external-identities",
            get(list_external_identities),
        )
        .route("/v1/auth/verify-password", post(verify_account_password))
        .route("/v1/auth/recovery/request", post(request_recovery))
        .route("/v1/auth/recovery/verify", post(verify_recovery))
        .route(
            "/v1/auth/recovery/reset-password",
            post(reset_account_password),
        )
        .route(
            "/v1/auth/recovery/authorize-unlock-reset",
            post(authorize_unlock_reset),
        )
        .route("/v1/auth/session", delete(logout))
        .route("/v1/devices", get(list_devices).post(register_device))
        .route("/v1/devices/{device_id}", delete(revoke_device))
        .route(
            "/v1/devices/{device_id}/control",
            get(poll_device_control).post(acknowledge_device_control),
        )
        .route("/v1/sync/push", post(push))
        .route("/v1/sync/pull", get(pull))
        .layer(DefaultBodyLimit::max(MAX_CIPHERTEXT_BYTES + 16 * 1024));
    let router = if protect_routes {
        router.layer(middleware::from_fn(require_handshake))
    } else {
        router
    };
    router
        .layer(middleware::from_fn(request_id))
        .layer(Extension(handshake))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
fn test_app(state: AppState) -> Router {
    build_app(state, false)
}

async fn request_id(mut request: Request<Body>, next: Next) -> Response {
    let request_id = Uuid::new_v4();
    let method = request.method().clone();
    let uri = request.uri().clone();
    request.extensions_mut().insert(request_id);
    let response = next.run(request).await;
    if response.status().is_server_error() {
        tracing::error!(
            %request_id,
            %method,
            %uri,
            status = %response.status(),
            "request completed with a server error"
        );
    }
    response
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        protocol_version: PROTOCOL_VERSION,
    })
}

async fn register(
    State(state): State<AppState>,
    Json(input): Json<CredentialsRequest>,
) -> Result<(StatusCode, Json<SessionResponse>), ApiError> {
    if !effective_registration_enabled(&state).await? {
        return Err(ApiError::RegistrationDisabled);
    }
    validate_credentials(&input, true)?;
    let phone = normalize_phone(
        input
            .phone
            .as_deref()
            .ok_or(ApiError::Validation("enter a valid mobile number"))?,
    )?;
    let user_id = Uuid::new_v4();
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(input.password.as_bytes(), &salt)
        .map_err(|_| ApiError::Internal)?
        .to_string();
    let result = sqlx::query(
        "INSERT INTO users (id, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id.to_string())
    .bind(input.email.trim().to_lowercase())
    .bind(phone)
    .bind(hash)
    .bind(now())
    .execute(&state.pool)
    .await;
    match result {
        Ok(_) => {
            let session = create_session(&state.pool, user_id).await?;
            Ok((StatusCode::CREATED, Json(session)))
        }
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            Err(ApiError::Conflict("account already exists"))
        }
        Err(_) => Err(ApiError::Internal),
    }
}

async fn login(
    State(state): State<AppState>,
    Json(input): Json<CredentialsRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    let user_id = verify_credentials(&state, &input).await?;
    Ok(Json(create_session(&state.pool, user_id).await?))
}

#[derive(Debug, Deserialize)]
struct IdcnAuthenticationRequest {
    provider_token: String,
    provider_account: Option<String>,
    provider_phone_code: Option<String>,
    provider_encrypted_password: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExternalSessionResponse {
    token: String,
    user_id: Uuid,
    expires_at: i64,
    provider: &'static str,
    display_identifier: String,
    linked_to_existing_account: bool,
}

#[derive(Debug, Serialize)]
struct ExternalIdentityResponse {
    provider: String,
    display_identifier: String,
    linked_at: i64,
}

#[derive(Debug)]
struct VerifiedIdcnIdentity {
    subject: String,
    display_identifier: String,
    profile_json: String,
}

async fn authenticate_idcn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<IdcnAuthenticationRequest>,
) -> Result<Json<ExternalSessionResponse>, ApiError> {
    let identity = verify_idcn_identity(&input).await?;
    let explicitly_authenticated_user = if headers.contains_key("authorization") {
        Some(authenticate(&state.pool, &headers).await?)
    } else {
        None
    };
    let existing_user: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM external_identities WHERE provider = ? AND provider_subject = ?",
    )
    .bind(IDCN_EXTERNAL_PROVIDER)
    .bind(&identity.subject)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| internal_error("external_identity.lookup", error))?;

    let (user_id, linked_to_existing_account) =
        match (explicitly_authenticated_user, existing_user.as_deref()) {
            (Some(current), Some(existing)) if existing != current.to_string() => {
                return Err(ApiError::Conflict(
                    "this IDCN Cloud account is already linked to another HeartLink account",
                ));
            }
            (Some(current), _) => (current, true),
            (None, Some(existing)) => (
                Uuid::parse_str(existing)
                    .map_err(|error| internal_error("external_identity.parse_user_id", error))?,
                true,
            ),
            (None, None) => {
                if !effective_registration_enabled(&state).await? {
                    return Err(ApiError::RegistrationDisabled);
                }
                (create_external_user(&state, &identity).await?, false)
            }
        };

    let current_binding: Option<String> = sqlx::query_scalar(
        "SELECT provider_subject FROM external_identities WHERE provider = ? AND user_id = ?",
    )
    .bind(IDCN_EXTERNAL_PROVIDER)
    .bind(user_id.to_string())
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| internal_error("external_identity.lookup_user_binding", error))?;
    if current_binding
        .as_deref()
        .is_some_and(|subject| subject != identity.subject)
    {
        return Err(ApiError::Conflict(
            "this HeartLink account is already linked to another IDCN Cloud account",
        ));
    }

    let timestamp = now();
    let upsert = match state.database_kind {
        DatabaseKind::Sqlite => {
            "INSERT INTO external_identities \
             (provider, provider_subject, user_id, display_identifier, profile_json, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(provider, provider_subject) DO UPDATE SET \
             display_identifier = excluded.display_identifier, profile_json = excluded.profile_json, updated_at = excluded.updated_at"
        }
        DatabaseKind::MySql => {
            "INSERT INTO external_identities \
             (provider, provider_subject, user_id, display_identifier, profile_json, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE display_identifier = VALUES(display_identifier), \
             profile_json = VALUES(profile_json), updated_at = VALUES(updated_at)"
        }
    };
    sqlx::query(upsert)
        .bind(IDCN_EXTERNAL_PROVIDER)
        .bind(&identity.subject)
        .bind(user_id.to_string())
        .bind(&identity.display_identifier)
        .bind(&identity.profile_json)
        .bind(timestamp)
        .bind(timestamp)
        .execute(&state.pool)
        .await
        .map_err(|error| internal_error("external_identity.upsert", error))?;
    let session = create_session(&state.pool, user_id).await?;
    Ok(Json(ExternalSessionResponse {
        token: session.token,
        user_id: session.user_id,
        expires_at: session.expires_at,
        provider: IDCN_EXTERNAL_PROVIDER,
        display_identifier: identity.display_identifier,
        linked_to_existing_account,
    }))
}

async fn list_external_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ExternalIdentityResponse>>, ApiError> {
    let user_id = authenticate(&state.pool, &headers).await?;
    let rows = sqlx::query(
        "SELECT provider, display_identifier, created_at FROM external_identities \
         WHERE user_id = ? ORDER BY created_at, provider",
    )
    .bind(user_id.to_string())
    .fetch_all(&state.pool)
    .await
    .map_err(|error| internal_error("external_identity.list", error))?;
    let identities = rows
        .into_iter()
        .map(|row| {
            Ok(ExternalIdentityResponse {
                provider: row.try_get("provider").map_err(|_| ApiError::Internal)?,
                display_identifier: row
                    .try_get("display_identifier")
                    .map_err(|_| ApiError::Internal)?,
                linked_at: row.try_get("created_at").map_err(|_| ApiError::Internal)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(identities))
}

async fn create_external_user(
    state: &AppState,
    identity: &VerifiedIdcnIdentity,
) -> Result<Uuid, ApiError> {
    let user_id = Uuid::new_v4();
    let email = format!(
        "idcn-{}@external.heartlink.invalid",
        blake3::hash(identity.subject.as_bytes()).to_hex()
    );
    let mut random_password = [0_u8; 48];
    OsRng.fill_bytes(&mut random_password);
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(URL_SAFE_NO_PAD.encode(random_password).as_bytes(), &salt)
        .map_err(|_| ApiError::Internal)?
        .to_string();
    sqlx::query(
        "INSERT INTO users (id, email, phone, password_hash, created_at) VALUES (?, ?, NULL, ?, ?)",
    )
    .bind(user_id.to_string())
    .bind(email)
    .bind(hash)
    .bind(now())
    .execute(&state.pool)
    .await
    .map_err(|error| internal_error("external_identity.create_user", error))?;
    Ok(user_id)
}

async fn verify_idcn_identity(
    input: &IdcnAuthenticationRequest,
) -> Result<VerifiedIdcnIdentity, ApiError> {
    let client = reqwest::Client::builder()
        // Keep the verifier wire-compatible with HeartLink's importer. IDCN
        // can additionally bind a bearer to the network that created it; the
        // encrypted-login fallback below obtains a server-local bearer.
        .user_agent("HeartLink-IDCN-Importer")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| internal_error("external_identity.http_client", error))?;
    let direct_token = input.provider_token.trim();
    if !direct_token.is_empty()
        && direct_token.len() <= MAX_EXTERNAL_TOKEN_BYTES
        && direct_token.bytes().all(|byte| byte.is_ascii_graphic())
        && let Ok(identity) = fetch_idcn_identity(&client, direct_token).await
    {
        return Ok(identity);
    }
    let token = exchange_idcn_login_proof(&client, input).await?;
    fetch_idcn_identity(&client, &token).await
}

async fn exchange_idcn_login_proof(
    client: &reqwest::Client,
    input: &IdcnAuthenticationRequest,
) -> Result<String, ApiError> {
    let account = input.provider_account.as_deref().unwrap_or_default().trim();
    let phone_code = input
        .provider_phone_code
        .as_deref()
        .unwrap_or_default()
        .trim();
    let encrypted_password = input
        .provider_encrypted_password
        .as_deref()
        .unwrap_or_default()
        .trim();
    if account.is_empty()
        || account.len() > 254
        || account.bytes().any(|byte| byte.is_ascii_control())
        || phone_code.is_empty()
        || phone_code.len() > 4
        || !phone_code.bytes().all(|byte| byte.is_ascii_digit())
        || encrypted_password.is_empty()
        || encrypted_password.len() > 2048
        || encrypted_password
            .bytes()
            .any(|byte| !byte.is_ascii_graphic())
    {
        return Err(ApiError::Unauthorized);
    }
    let response = client
        .post(IDCN_LOGIN_ENDPOINT)
        .header("accept", "application/json")
        .json(&serde_json::json!({
            "type": "password",
            "account": account,
            "phone_code": phone_code,
            "password": encrypted_password,
            "remember_password": 0,
        }))
        .send()
        .await
        .map_err(|_| ApiError::Unauthorized)?;
    if !response.status().is_success() {
        return Err(ApiError::Unauthorized);
    }
    let body: serde_json::Value = response.json().await.map_err(|_| ApiError::Unauthorized)?;
    let code = body.get("code").and_then(serde_json::Value::as_i64);
    if code.is_some_and(|value| value != 0 && value != 200) {
        return Err(ApiError::Unauthorized);
    }
    body.get("data")
        .and_then(|value| value.get("jwt"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_EXTERNAL_TOKEN_BYTES
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .map(str::to_owned)
        .ok_or(ApiError::Unauthorized)
}

async fn fetch_idcn_identity(
    client: &reqwest::Client,
    token: &str,
) -> Result<VerifiedIdcnIdentity, ApiError> {
    let response = client
        .get(IDCN_ACCOUNT_ENDPOINT)
        .bearer_auth(token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|_| ApiError::Unauthorized)?;
    if !response.status().is_success() {
        return Err(ApiError::Unauthorized);
    }
    let body: serde_json::Value = response.json().await.map_err(|_| ApiError::Unauthorized)?;
    parse_idcn_identity(&body).ok_or(ApiError::Unauthorized)
}

fn parse_idcn_identity(body: &serde_json::Value) -> Option<VerifiedIdcnIdentity> {
    let mut data = body.get("data")?;
    if let Some(account) = data.get("account") {
        data = account;
    }
    let subject = data.get("id").and_then(|value| match value {
        serde_json::Value::String(value) => Some(value.trim().to_owned()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    })?;
    if subject.is_empty() || subject.len() > 191 {
        return None;
    }
    let safe_string = |key: &str| {
        data.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let phone = safe_string("phone");
    let email = safe_string("email");
    let username = safe_string("username");
    let display_identifier = phone
        .clone()
        .or(email.clone())
        .or(username.clone())
        .unwrap_or_else(|| format!("IDCN {subject}"));
    let profile_json = serde_json::json!({
        "id": subject,
        "phone": phone,
        "email": email,
        "username": username,
    })
    .to_string();
    Some(VerifiedIdcnIdentity {
        subject,
        display_identifier,
        profile_json,
    })
}

async fn verify_account_password(
    State(state): State<AppState>,
    Json(input): Json<CredentialsRequest>,
) -> Result<StatusCode, ApiError> {
    verify_credentials(&state, &input).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_credentials(
    state: &AppState,
    input: &CredentialsRequest,
) -> Result<Uuid, ApiError> {
    validate_credentials(input, false)?;
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE email = ?")
        .bind(input.email.trim().to_lowercase())
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;
    let hash: String = row
        .try_get("password_hash")
        .map_err(|_| ApiError::Internal)?;
    let parsed = PasswordHash::new(&hash).map_err(|_| ApiError::Internal)?;
    Argon2::default()
        .verify_password(input.password.as_bytes(), &parsed)
        .map_err(|_| ApiError::Unauthorized)?;
    let id: String = row.try_get("id").map_err(|_| ApiError::Internal)?;
    Uuid::parse_str(&id).map_err(|_| ApiError::Internal)
}

async fn request_recovery(
    State(state): State<AppState>,
    Json(input): Json<RecoveryRequest>,
) -> Result<(StatusCode, Json<RecoveryChallengeResponse>), ApiError> {
    if !recovery_supported(&state, input.channel).await? {
        return Err(ApiError::RecoveryUnavailable);
    }
    let identifier = input.identifier.trim();
    if identifier.is_empty() || identifier.len() > 254 {
        return Err(ApiError::Validation(
            "enter a registered email or mobile number",
        ));
    }
    let email_identifier = identifier.to_lowercase();
    let phone_identifier = normalize_phone(identifier).unwrap_or_default();
    let row = sqlx::query("SELECT id, email, phone FROM users WHERE email = ? OR phone = ?")
        .bind(email_identifier)
        .bind(phone_identifier)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?;
    let timestamp = now();
    let expires_at = timestamp + RECOVERY_CODE_LIFETIME_SECONDS;
    let fallback_id = Uuid::new_v4();
    let Some(row) = row else {
        // Account enumeration resistance: callers receive the same accepted
        // shape even when no matching account exists.
        return Ok((
            StatusCode::ACCEPTED,
            Json(RecoveryChallengeResponse {
                challenge_id: fallback_id,
                destination_hint: "已登记的联系方式".to_owned(),
                expires_at,
            }),
        ));
    };
    let user_id: String = row.try_get("id").map_err(|_| ApiError::Internal)?;
    let purpose = recovery_purpose_to_str(input.purpose);
    let channel = recovery_channel_to_str(input.channel);
    if let Some(existing) = sqlx::query(
        "SELECT id, expires_at FROM recovery_challenges \
         WHERE user_id = ? AND purpose = ? AND channel = ? \
           AND consumed_at IS NULL AND created_at > ? \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&user_id)
    .bind(purpose)
    .bind(channel)
    .bind(timestamp - RECOVERY_RESEND_SECONDS)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| ApiError::Internal)?
    {
        let id: String = existing.try_get("id").map_err(|_| ApiError::Internal)?;
        let destination = recovery_destination(&row, input.channel)?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(RecoveryChallengeResponse {
                challenge_id: Uuid::parse_str(&id).map_err(|_| ApiError::Internal)?,
                destination_hint: mask_destination(&destination, input.channel),
                expires_at: existing
                    .try_get("expires_at")
                    .map_err(|_| ApiError::Internal)?,
            }),
        ));
    }

    let destination = recovery_destination(&row, input.channel)?;
    let challenge_id = Uuid::new_v4();
    let code = generate_recovery_code();
    let code_hash = recovery_code_hash(&state.recovery_pepper, challenge_id, &code);
    sqlx::query(
        "INSERT INTO recovery_challenges \
         (id, user_id, purpose, channel, code_hash, expires_at, attempts, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
    )
    .bind(challenge_id.to_string())
    .bind(&user_id)
    .bind(purpose)
    .bind(channel)
    .bind(code_hash)
    .bind(expires_at)
    .bind(timestamp)
    .execute(&state.pool)
    .await
    .map_err(|_| ApiError::Internal)?;

    let delivery_result = deliver_recovery(
        &state,
        RecoveryMessage {
            channel: input.channel,
            destination: destination.clone(),
            code,
            purpose: input.purpose,
            expires_in_seconds: RECOVERY_CODE_LIFETIME_SECONDS,
        },
    )
    .await;
    if let Err(error) = delivery_result {
        let _ = sqlx::query("DELETE FROM recovery_challenges WHERE id = ?")
            .bind(challenge_id.to_string())
            .execute(&state.pool)
            .await;
        return Err(error);
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(RecoveryChallengeResponse {
            challenge_id,
            destination_hint: mask_destination(&destination, input.channel),
            expires_at,
        }),
    ))
}

async fn verify_recovery(
    State(state): State<AppState>,
    Json(input): Json<RecoveryVerifyRequest>,
) -> Result<Json<RecoveryVerifiedResponse>, ApiError> {
    if input.code.len() != 6 || !input.code.bytes().all(|value| value.is_ascii_digit()) {
        return Err(ApiError::InvalidRecovery);
    }
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let row = sqlx::query(
        "SELECT user_id, purpose, code_hash, expires_at, attempts, consumed_at \
         FROM recovery_challenges WHERE id = ?",
    )
    .bind(input.challenge_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::InvalidRecovery)?;
    let expires_at: i64 = row.try_get("expires_at").map_err(|_| ApiError::Internal)?;
    let attempts: i64 = row.try_get("attempts").map_err(|_| ApiError::Internal)?;
    let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(|_| ApiError::Internal)?;
    if expires_at <= now() || attempts >= RECOVERY_MAX_ATTEMPTS || consumed_at.is_some() {
        return Err(ApiError::InvalidRecovery);
    }
    sqlx::query("UPDATE recovery_challenges SET attempts = attempts + 1 WHERE id = ?")
        .bind(input.challenge_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    let expected: String = row.try_get("code_hash").map_err(|_| ApiError::Internal)?;
    let actual = recovery_code_hash(&state.recovery_pepper, input.challenge_id, &input.code);
    if !constant_time_text_equals(&actual, &expected) {
        tx.commit().await.map_err(|_| ApiError::Internal)?;
        return Err(ApiError::InvalidRecovery);
    }
    let consumed = sqlx::query(
        "UPDATE recovery_challenges SET consumed_at = ? \
         WHERE id = ? AND consumed_at IS NULL",
    )
    .bind(now())
    .bind(input.challenge_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::InvalidRecovery);
    }
    let user_id: String = row.try_get("user_id").map_err(|_| ApiError::Internal)?;
    let purpose_value: String = row.try_get("purpose").map_err(|_| ApiError::Internal)?;
    let purpose = str_to_recovery_purpose(&purpose_value).ok_or(ApiError::Internal)?;
    let recovery_token = generate_token();
    let token_expires_at = now() + RECOVERY_TOKEN_LIFETIME_SECONDS;
    sqlx::query(
        "INSERT INTO recovery_tokens \
         (token_hash, user_id, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(token_hash(&recovery_token))
    .bind(user_id)
    .bind(recovery_purpose_to_str(purpose))
    .bind(token_expires_at)
    .bind(now())
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(Json(RecoveryVerifiedResponse {
        recovery_token,
        purpose,
        expires_at: token_expires_at,
    }))
}

async fn reset_account_password(
    State(state): State<AppState>,
    Json(input): Json<RecoveryResetPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    validate_password(&input.new_password)?;
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(input.new_password.as_bytes(), &salt)
        .map_err(|_| ApiError::Internal)?
        .to_string();
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let user_id = consume_recovery_token(
        &mut tx,
        &input.recovery_token,
        RecoveryPurpose::AccountPassword,
    )
    .await?;
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(password_hash)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    // A password reset invalidates stolen account sessions on every device.
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize_unlock_reset(
    State(state): State<AppState>,
    Json(input): Json<RecoveryAuthorizeUnlockRequest>,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    consume_recovery_token(
        &mut tx,
        &input.recovery_token,
        RecoveryPurpose::UnlockPassword,
    )
    .await?;
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let token = bearer_token(&headers)?;
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(token_hash(token))
        .execute(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegisterDeviceRequest>,
) -> Result<StatusCode, ApiError> {
    let user_id = authenticate(&state.pool, &headers).await?;
    if input.name.trim().is_empty() || input.name.len() > 120 || input.platform.len() > 40 {
        return Err(ApiError::Validation("invalid device metadata"));
    }
    let control_token_hash = input
        .control_token
        .as_deref()
        .map(validate_device_control_token)
        .transpose()?
        .map(token_hash);
    let current_session_hash = token_hash(bearer_token(&headers)?);
    let heartbeat_at = now();
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let replaced_devices = sqlx::query(
        "SELECT id, control_token_hash FROM devices \
         WHERE user_id = ? AND name = ? AND platform = ? AND id <> ? AND revoked_at IS NULL",
    )
    .bind(user_id.to_string())
    .bind(input.name.trim())
    .bind(input.platform.trim())
    .bind(input.device_id.to_string())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    for row in replaced_devices {
        let replaced_device_id: String = row.try_get("id").map_err(|_| ApiError::Internal)?;
        let replaced_control_hash: Option<String> = row
            .try_get("control_token_hash")
            .map_err(|_| ApiError::Internal)?;
        sqlx::query(
            "UPDATE devices SET revoked_at = ? \
             WHERE user_id = ? AND id = ? AND revoked_at IS NULL",
        )
        .bind(heartbeat_at)
        .bind(user_id.to_string())
        .bind(&replaced_device_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
        if replaced_control_hash.is_some() {
            queue_remote_wipe(&mut tx, user_id, &replaced_device_id, heartbeat_at).await?;
        }
        sqlx::query(
            "DELETE FROM sessions \
             WHERE user_id = ? AND device_id = ? AND token_hash <> ?",
        )
        .bind(user_id.to_string())
        .bind(&replaced_device_id)
        .bind(&current_session_hash)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
        write_device_audit(
            &mut tx,
            "device.replace.revoke",
            user_id,
            &replaced_device_id,
            None,
            heartbeat_at,
        )
        .await?;
    }
    let statement = match state.database_kind {
        DatabaseKind::Sqlite => {
            "INSERT INTO devices (id, user_id, name, platform, created_at, last_seen_at, control_token_hash) VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id, user_id) DO UPDATE SET name = excluded.name, platform = excluded.platform, revoked_at = NULL, last_seen_at = excluded.last_seen_at, control_token_hash = COALESCE(excluded.control_token_hash, devices.control_token_hash)"
        }
        DatabaseKind::MySql => {
            "INSERT INTO devices (id, user_id, name, platform, created_at, last_seen_at, control_token_hash) VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE name = VALUES(name), platform = VALUES(platform), revoked_at = NULL, last_seen_at = VALUES(last_seen_at), control_token_hash = COALESCE(VALUES(control_token_hash), control_token_hash)"
        }
    };
    sqlx::query(statement)
        .bind(input.device_id.to_string())
        .bind(user_id.to_string())
        .bind(input.name.trim())
        .bind(input.platform.trim())
        .bind(heartbeat_at)
        .bind(heartbeat_at)
        .bind(control_token_hash)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "UPDATE sessions SET device_id = ? WHERE token_hash = ? AND user_id = ? AND expires_at > ?",
    )
    .bind(input.device_id.to_string())
    .bind(current_session_hash)
    .bind(user_id.to_string())
    .bind(heartbeat_at)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    let user_id = authenticate(&state.pool, &headers).await?;
    let heartbeat_at = now();
    if let Some(device_id) = request_device_id(&headers) {
        sqlx::query(
            "UPDATE devices SET last_seen_at = ? \
             WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
        )
        .bind(heartbeat_at)
        .bind(device_id.to_string())
        .bind(user_id.to_string())
        .execute(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?;
        let token = bearer_token(&headers)?;
        sqlx::query(
            "UPDATE sessions SET device_id = ? WHERE token_hash = ? AND user_id = ? AND expires_at > ?",
        )
        .bind(device_id.to_string())
        .bind(token_hash(token))
        .bind(user_id.to_string())
        .bind(heartbeat_at)
        .execute(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?;
    }
    let rows = sqlx::query(
        "SELECT id, name, platform, revoked_at, created_at, last_seen_at, control_token_hash FROM devices \
         WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC",
    )
    .bind(user_id.to_string())
    .fetch_all(&state.pool)
    .await
    .map_err(|_| ApiError::Internal)?;
    let mut devices = Vec::with_capacity(rows.len());
    let mut seen_devices = HashSet::new();
    for row in rows {
        let id: String = row.try_get("id").map_err(|_| ApiError::Internal)?;
        let name: String = row.try_get("name").map_err(|_| ApiError::Internal)?;
        let platform: String = row.try_get("platform").map_err(|_| ApiError::Internal)?;
        let identity = format!(
            "{}\u{0}{}",
            name.trim().to_lowercase(),
            platform.trim().to_lowercase()
        );
        if !seen_devices.insert(identity) {
            continue;
        }
        let last_seen_at = row
            .try_get("last_seen_at")
            .map_err(|_| ApiError::Internal)?;
        devices.push(DeviceResponse {
            device_id: Uuid::parse_str(&id).map_err(|_| ApiError::Internal)?,
            name,
            platform,
            revoked: false,
            created_at: row.try_get("created_at").map_err(|_| ApiError::Internal)?,
            last_seen_at,
            online: last_seen_at >= heartbeat_at - DEVICE_ONLINE_WINDOW_SECONDS,
            remote_control_enabled: row
                .try_get::<Option<String>, _>("control_token_hash")
                .map_err(|_| ApiError::Internal)?
                .is_some(),
        });
    }
    Ok(Json(devices))
}

#[derive(Deserialize)]
struct RevokeDeviceRequest {
    password: String,
}

async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
    input: Option<Json<RevokeDeviceRequest>>,
) -> Result<StatusCode, ApiError> {
    let user_id = authenticate(&state.pool, &headers).await?;
    let password = input
        .as_ref()
        .map(|Json(value)| value.password.as_str())
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or(ApiError::Unauthorized)?;
    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;
    let parsed = PasswordHash::new(&password_hash).map_err(|_| ApiError::Internal)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| ApiError::Unauthorized)?;
    let target = sqlx::query(
        "SELECT id, control_token_hash FROM devices \
         WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(device_id.to_string())
    .bind(user_id.to_string())
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| ApiError::Internal)?;
    let Some(target) = target else {
        return Err(ApiError::NotFound(
            "device was not found or already revoked",
        ));
    };
    let _: String = target.try_get("id").map_err(|_| ApiError::Internal)?;
    let remote_control_enabled = target
        .try_get::<Option<String>, _>("control_token_hash")
        .map_err(|_| ApiError::Internal)?
        .is_some();
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let revoked_at = now();
    let result = sqlx::query(
        "UPDATE devices SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(revoked_at)
    .bind(device_id.to_string())
    .bind(user_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound(
            "device was not found or already revoked",
        ));
    }
    let command_id = if remote_control_enabled {
        Some(queue_remote_wipe(&mut tx, user_id, &device_id.to_string(), revoked_at).await?)
    } else {
        None
    };
    sqlx::query("DELETE FROM sessions WHERE user_id = ? AND device_id = ?")
        .bind(user_id.to_string())
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    write_device_audit(
        &mut tx,
        "device.revoke",
        user_id,
        &device_id.to_string(),
        command_id,
        revoked_at,
    )
    .await?;
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn poll_device_control(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<Json<DeviceControlResponse>, ApiError> {
    let control_token = device_control_token(&headers)?;
    let row = sqlx::query(
        "SELECT user_id, revoked_at FROM devices \
         WHERE id = ? AND control_token_hash = ?",
    )
    .bind(device_id.to_string())
    .bind(token_hash(control_token))
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::Unauthorized)?;
    let user_id: String = row.try_get("user_id").map_err(|_| ApiError::Internal)?;
    let revoked_at: Option<i64> = row.try_get("revoked_at").map_err(|_| ApiError::Internal)?;
    let checked_at = now();
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ? AND user_id = ?")
        .bind(checked_at)
        .bind(device_id.to_string())
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    let command_row = if revoked_at.is_some() {
        sqlx::query(
            "SELECT id, action, issued_at, delivered_at FROM device_commands \
             WHERE user_id = ? AND device_id = ? AND acknowledged_at IS NULL \
             ORDER BY issued_at ASC LIMIT 1",
        )
        .bind(&user_id)
        .bind(device_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?
    } else {
        None
    };
    let command = if let Some(command_row) = command_row {
        let command_id: String = command_row.try_get("id").map_err(|_| ApiError::Internal)?;
        let action: String = command_row
            .try_get("action")
            .map_err(|_| ApiError::Internal)?;
        if action != "wipe_local_data_and_logout" {
            return Err(ApiError::Internal);
        }
        let delivered_at: Option<i64> = command_row
            .try_get("delivered_at")
            .map_err(|_| ApiError::Internal)?;
        if delivered_at.is_none() {
            let delivered = sqlx::query(
                "UPDATE device_commands SET delivered_at = ? \
                 WHERE id = ? AND delivered_at IS NULL",
            )
            .bind(checked_at)
            .bind(&command_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Internal)?;
            if delivered.rows_affected() == 1 {
                write_device_audit(
                    &mut tx,
                    "device.wipe.delivered",
                    Uuid::parse_str(&user_id).map_err(|_| ApiError::Internal)?,
                    &device_id.to_string(),
                    Some(Uuid::parse_str(&command_id).map_err(|_| ApiError::Internal)?),
                    checked_at,
                )
                .await?;
            }
        }
        Some(DeviceControlCommand {
            command_id: Uuid::parse_str(&command_id).map_err(|_| ApiError::Internal)?,
            action: DeviceControlAction::WipeLocalDataAndLogout,
            issued_at: command_row
                .try_get("issued_at")
                .map_err(|_| ApiError::Internal)?,
        })
    } else {
        None
    };
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(Json(DeviceControlResponse {
        revoked: revoked_at.is_some(),
        command,
    }))
}

async fn acknowledge_device_control(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
    Json(input): Json<AcknowledgeDeviceControlRequest>,
) -> Result<StatusCode, ApiError> {
    let control_token = device_control_token(&headers)?;
    let row = sqlx::query("SELECT user_id FROM devices WHERE id = ? AND control_token_hash = ?")
        .bind(device_id.to_string())
        .bind(token_hash(control_token))
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;
    let user_id: String = row.try_get("user_id").map_err(|_| ApiError::Internal)?;
    let acknowledged_at = now();
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let updated = sqlx::query(
        "UPDATE device_commands SET delivered_at = COALESCE(delivered_at, ?), acknowledged_at = ? \
         WHERE id = ? AND user_id = ? AND device_id = ? AND acknowledged_at IS NULL",
    )
    .bind(acknowledged_at)
    .bind(acknowledged_at)
    .bind(input.command_id.to_string())
    .bind(&user_id)
    .bind(device_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    if updated.rows_affected() == 0 {
        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_commands \
             WHERE id = ? AND user_id = ? AND device_id = ? AND acknowledged_at IS NOT NULL",
        )
        .bind(input.command_id.to_string())
        .bind(&user_id)
        .bind(device_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
        if exists != 1 {
            return Err(ApiError::NotFound("device command was not found"));
        }
    } else {
        write_device_audit(
            &mut tx,
            "device.wipe.acknowledged",
            Uuid::parse_str(&user_id).map_err(|_| ApiError::Internal)?,
            &device_id.to_string(),
            Some(input.command_id),
            acknowledged_at,
        )
        .await?;
    }
    sqlx::query("DELETE FROM sessions WHERE user_id = ? AND device_id = ?")
        .bind(&user_id)
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn queue_remote_wipe(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    user_id: Uuid,
    device_id: &str,
    issued_at: i64,
) -> Result<Uuid, ApiError> {
    let command_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO device_commands \
         (id, user_id, device_id, action, issued_at, delivered_at, acknowledged_at) \
         VALUES (?, ?, ?, ?, ?, NULL, NULL)",
    )
    .bind(command_id.to_string())
    .bind(user_id.to_string())
    .bind(device_id)
    .bind("wipe_local_data_and_logout")
    .bind(issued_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    Ok(command_id)
}

async fn write_device_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    action: &str,
    user_id: Uuid,
    device_id: &str,
    command_id: Option<Uuid>,
    created_at: i64,
) -> Result<(), ApiError> {
    let target = if let Some(command_id) = command_id {
        format!("user={user_id};device={device_id};command={command_id}")
    } else {
        format!("user={user_id};device={device_id};remote_control=unavailable")
    };
    sqlx::query(
        "INSERT INTO admin_audit_events (id, action, target, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(action)
    .bind(target)
    .bind(created_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    Ok(())
}

async fn push(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PushRequest>,
) -> Result<Json<PushResponse>, ApiError> {
    let user_id = authenticate(&state.pool, &headers).await?;
    validate_record(&input.record)?;
    enforce_storage_quota(&state, user_id, &input.record).await?;
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let active_device: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(input.record.device_id.to_string())
    .bind(user_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    if active_device != 1 {
        return Err(ApiError::Forbidden(
            "device is not registered or was revoked",
        ));
    }
    // MySQL exposes the unsigned data_version column through SQLx Any as an
    // unsigned wire type. Normalize it to a signed integer so this gate has
    // identical decoding behavior on SQLite and MySQL. The MySQL row lock also
    // keeps a concurrent writer from lowering the version between this check
    // and the upsert below.
    let current_record_query = match state.database_kind {
        DatabaseKind::Sqlite => {
            "SELECT current_revision, data_version FROM records WHERE user_id = ? AND record_id = ?"
        }
        DatabaseKind::MySql => {
            "SELECT current_revision, CAST(data_version AS SIGNED) AS data_version FROM records WHERE user_id = ? AND record_id = ? FOR UPDATE"
        }
    };
    let current = sqlx::query(current_record_query)
        .bind(user_id.to_string())
        .bind(input.record.id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| internal_error("sync.push.fetch_current_record", error))?;
    let (expected, current_data_version) = if let Some(row) = current {
        (
            row.try_get::<i64, _>("current_revision")
                .map_err(|error| internal_error("sync.push.decode_current_revision", error))?,
            row.try_get::<i64, _>("data_version")
                .map_err(|error| internal_error("sync.push.decode_data_version", error))?,
        )
    } else {
        (0, 0)
    };
    if input.record.base_revision != expected {
        sqlx::query(
            "INSERT INTO conflict_versions (conflict_id, user_id, record_id, submitted_kind, submitted_ciphertext, submitted_data_version, submitted_base_revision, submitted_deleted, current_revision, device_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id.to_string())
        .bind(input.record.id.to_string())
        .bind(kind_to_str(input.record.kind))
        .bind(&input.record.ciphertext)
        .bind(i64::from(input.record.data_version))
        .bind(input.record.base_revision)
        .bind(input.record.deleted)
        .bind(expected)
        .bind(input.record.device_id.to_string())
        .bind(now())
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
        tx.commit().await.map_err(|_| ApiError::Internal)?;
        return Err(ApiError::RevisionConflict(expected));
    }
    if i64::from(input.record.data_version) < current_data_version {
        return Err(ApiError::ClientUpgradeRequired {
            current: current_data_version,
            submitted: i64::from(input.record.data_version),
        });
    }
    let revision: i64 = match state.database_kind {
        DatabaseKind::Sqlite => sqlx::query_scalar(
            "UPDATE users SET next_revision = next_revision + 1 WHERE id = ? RETURNING next_revision",
        )
        .bind(user_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?,
        DatabaseKind::MySql => {
            let current_revision: i64 =
                sqlx::query_scalar("SELECT next_revision FROM users WHERE id = ? FOR UPDATE")
                    .bind(user_id.to_string())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| ApiError::Internal)?;
            let next_revision = current_revision + 1;
            sqlx::query("UPDATE users SET next_revision = ? WHERE id = ?")
                .bind(next_revision)
                .bind(user_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|_| ApiError::Internal)?;
            next_revision
        }
    };
    let timestamp = now();
    let kind = kind_to_str(input.record.kind);
    let upsert_record = match state.database_kind {
        DatabaseKind::Sqlite => {
            "INSERT INTO records (user_id, record_id, kind, ciphertext, data_version, current_revision, deleted, device_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(user_id, record_id) DO UPDATE SET kind=excluded.kind, ciphertext=excluded.ciphertext, data_version=excluded.data_version, current_revision=excluded.current_revision, deleted=excluded.deleted, device_id=excluded.device_id, updated_at=excluded.updated_at"
        }
        DatabaseKind::MySql => {
            "INSERT INTO records (user_id, record_id, kind, ciphertext, data_version, current_revision, deleted, device_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE kind=VALUES(kind), ciphertext=VALUES(ciphertext), data_version=VALUES(data_version), current_revision=VALUES(current_revision), deleted=VALUES(deleted), device_id=VALUES(device_id), updated_at=VALUES(updated_at)"
        }
    };
    sqlx::query(upsert_record)
        .bind(user_id.to_string())
        .bind(input.record.id.to_string())
        .bind(kind)
        .bind(&input.record.ciphertext)
        .bind(i64::from(input.record.data_version))
        .bind(revision)
        .bind(input.record.deleted)
        .bind(input.record.device_id.to_string())
        .bind(timestamp)
        .bind(timestamp)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "INSERT INTO revision_events (user_id, revision, record_id, kind, ciphertext, data_version, base_revision, deleted, device_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id.to_string()).bind(revision).bind(input.record.id.to_string()).bind(kind)
    .bind(&input.record.ciphertext).bind(i64::from(input.record.data_version)).bind(input.record.base_revision)
    .bind(input.record.deleted).bind(input.record.device_id.to_string()).bind(timestamp)
    .execute(&mut *tx).await.map_err(|_| ApiError::Internal)?;
    sqlx::query("DELETE FROM revision_events WHERE user_id = ? AND revision <= ?")
        .bind(user_id.to_string())
        .bind((revision - MAX_REVISIONS_PER_USER).max(0))
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
    let conflict_cutoff: Option<i64> = sqlx::query_scalar(
        "SELECT created_at FROM conflict_versions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1 OFFSET ?",
    )
    .bind(user_id.to_string())
    .bind(MAX_CONFLICTS_PER_USER - 1)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    if let Some(cutoff) = conflict_cutoff {
        sqlx::query("DELETE FROM conflict_versions WHERE user_id = ? AND created_at < ?")
            .bind(user_id.to_string())
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Internal)?;
    }
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(Json(PushResponse { revision }))
}

#[derive(Debug, Deserialize)]
struct PullQuery {
    #[serde(default)]
    since: i64,
}

async fn pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PullQuery>,
) -> Result<Json<PullResponse>, ApiError> {
    let user_id = authenticate(&state.pool, &headers).await?;
    if query.since < 0 {
        return Err(ApiError::Validation("revision cursor cannot be negative"));
    }
    // A bootstrap pull needs the current state, not every historical copy of
    // that state. Returning revision_events from zero made a single encrypted
    // snapshot appear up to MAX_REVISIONS_PER_USER times and could turn a
    // sub-megabyte vault into a response far above the client's safety limit.
    // Incremental pulls keep their event semantics; only `since=0` is folded
    // through the records table.
    //
    // SQLx Any preserves MySQL's unsigned BIGINT and TINYINT wire types.
    // Normalize them in SQL so the shared decoder sees the same signed integer
    // representation that SQLite exposes.
    let rows = if query.since == 0 {
        let snapshot_query = match state.database_kind {
            DatabaseKind::Sqlite => {
                "SELECT current_revision AS revision, record_id, kind, ciphertext, data_version, 0 AS base_revision, deleted, device_id, updated_at FROM records WHERE user_id = ? ORDER BY current_revision ASC LIMIT 1000"
            }
            DatabaseKind::MySql => {
                "SELECT current_revision AS revision, record_id, kind, ciphertext, CAST(data_version AS SIGNED) AS data_version, 0 AS base_revision, CAST(deleted AS SIGNED) AS deleted, device_id, updated_at FROM records WHERE user_id = ? ORDER BY current_revision ASC LIMIT 1000"
            }
        };
        sqlx::query(snapshot_query)
            .bind(user_id.to_string())
            .fetch_all(&state.pool)
            .await
            .map_err(|error| internal_error("sync.pull.fetch_snapshot", error))?
    } else {
        let event_query = match state.database_kind {
            DatabaseKind::Sqlite => {
                "SELECT revision, record_id, kind, ciphertext, data_version, base_revision, deleted, device_id, updated_at FROM revision_events WHERE user_id = ? AND revision > ? ORDER BY revision ASC LIMIT 1000"
            }
            DatabaseKind::MySql => {
                "SELECT revision, record_id, kind, ciphertext, CAST(data_version AS SIGNED) AS data_version, base_revision, CAST(deleted AS SIGNED) AS deleted, device_id, updated_at FROM revision_events WHERE user_id = ? AND revision > ? ORDER BY revision ASC LIMIT 1000"
            }
        };
        sqlx::query(event_query)
            .bind(user_id.to_string())
            .bind(query.since)
            .fetch_all(&state.pool)
            .await
            .map_err(|error| internal_error("sync.pull.fetch_events", error))?
    };
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let record_id: String = row
            .try_get("record_id")
            .map_err(|error| internal_error("sync.pull.decode_record_id", error))?;
        let device_id: String = row
            .try_get("device_id")
            .map_err(|error| internal_error("sync.pull.decode_device_id", error))?;
        let kind: String = row
            .try_get("kind")
            .map_err(|error| internal_error("sync.pull.decode_kind", error))?;
        // SQLx Any exposes MySQL MEDIUMTEXT columns as BLOB values while
        // SQLite exposes the same schema field as TEXT. Decode the MySQL bytes
        // explicitly so both backends produce the protocol's UTF-8 string.
        let ciphertext = match state.database_kind {
            DatabaseKind::Sqlite => row
                .try_get::<String, _>("ciphertext")
                .map_err(|error| internal_error("sync.pull.decode_ciphertext", error))?,
            DatabaseKind::MySql => {
                let bytes = row
                    .try_get::<Vec<u8>, _>("ciphertext")
                    .map_err(|error| internal_error("sync.pull.decode_ciphertext", error))?;
                String::from_utf8(bytes)
                    .map_err(|error| internal_error("sync.pull.decode_ciphertext_utf8", error))?
            }
        };
        records.push(RevisionedRecord {
            record: CipherRecord {
                id: Uuid::parse_str(&record_id)
                    .map_err(|error| internal_error("sync.pull.parse_record_id", error))?,
                kind: str_to_kind(&kind).ok_or_else(|| {
                    tracing::error!(kind, "sync pull returned an unknown record kind");
                    ApiError::Internal
                })?,
                ciphertext,
                data_version: row
                    .try_get::<i64, _>("data_version")
                    .map_err(|error| internal_error("sync.pull.decode_data_version", error))?
                    as u32,
                base_revision: row
                    .try_get("base_revision")
                    .map_err(|error| internal_error("sync.pull.decode_base_revision", error))?,
                deleted: row
                    .try_get::<i64, _>("deleted")
                    .map_err(|error| internal_error("sync.pull.decode_deleted", error))?
                    != 0,
                device_id: Uuid::parse_str(&device_id)
                    .map_err(|error| internal_error("sync.pull.parse_device_id", error))?,
            },
            revision: row
                .try_get("revision")
                .map_err(|error| internal_error("sync.pull.decode_revision", error))?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|error| internal_error("sync.pull.decode_updated_at", error))?,
        });
    }
    let cursor: i64 = sqlx::query_scalar("SELECT next_revision FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_one(&state.pool)
        .await
        .map_err(|error| internal_error("sync.pull.fetch_cursor", error))?;
    Ok(Json(PullResponse { records, cursor }))
}

fn internal_error(operation: &'static str, error: impl std::fmt::Display) -> ApiError {
    tracing::error!(operation, error = %error, "database or record decoding failed");
    ApiError::Internal
}

#[derive(Default)]
struct DynamicRecoverySettings {
    smtp_enabled: bool,
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    smtp_from: String,
    smtp_starttls: bool,
    sms_enabled: bool,
    sms_provider: String,
    sms_webhook_url: String,
    sms_webhook_token: String,
    aliyun_sms_access_key_id: String,
    aliyun_sms_access_key_secret: String,
    aliyun_sms_sign_name: String,
    aliyun_sms_template_code: String,
}

async fn recovery_supported(state: &AppState, channel: RecoveryChannel) -> Result<bool, ApiError> {
    let configured = load_dynamic_recovery_settings(state).await?;
    let dynamic = match channel {
        RecoveryChannel::Email => {
            configured.smtp_enabled
                && !configured.smtp_host.is_empty()
                && !configured.smtp_from.is_empty()
        }
        RecoveryChannel::Phone => {
            configured.sms_enabled
                && match configured.sms_provider.as_str() {
                    "aliyun" => {
                        !configured.aliyun_sms_access_key_id.is_empty()
                            && !configured.aliyun_sms_access_key_secret.is_empty()
                            && !configured.aliyun_sms_sign_name.is_empty()
                            && configured.aliyun_sms_template_code.starts_with("SMS_")
                    }
                    "webhook" => configured.sms_webhook_url.starts_with("https://"),
                    _ => false,
                }
        }
    };
    Ok(dynamic || state.recovery_delivery.supports(channel))
}

async fn deliver_recovery(state: &AppState, message: RecoveryMessage) -> Result<(), ApiError> {
    let configured = load_dynamic_recovery_settings(state).await?;
    match message.channel {
        RecoveryChannel::Email
            if configured.smtp_enabled
                && !configured.smtp_host.is_empty()
                && !configured.smtp_from.is_empty() =>
        {
            let from = configured
                .smtp_from
                .parse()
                .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
            let to = message
                .destination
                .parse()
                .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
            let purpose = match message.purpose {
                RecoveryPurpose::AccountPassword => "重置云端账户密码",
                RecoveryPurpose::UnlockPassword => "重置 HeartLink 锁屏密码",
            };
            let email = Message::builder()
                .from(from)
                .to(to)
                .subject("HeartLink 安全验证码")
                .body(format!(
                    "你正在{purpose}。\n\n验证码：{}\n\n验证码将在 {} 分钟后失效。如果不是你本人操作，请忽略本邮件。",
                    message.code,
                    message.expires_in_seconds / 60
                ))
                .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
            let mut builder = if configured.smtp_starttls {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&configured.smtp_host)
                    .map_err(|_| ApiError::RecoveryDeliveryFailed)?
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&configured.smtp_host)
            };
            builder = builder.port(configured.smtp_port.max(1));
            if !configured.smtp_username.is_empty() {
                builder = builder.credentials(Credentials::new(
                    configured.smtp_username,
                    configured.smtp_password,
                ));
            }
            builder
                .build()
                .send(email)
                .await
                .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
            Ok(())
        }
        RecoveryChannel::Phone if configured.sms_enabled && configured.sms_provider == "aliyun" => {
            deliver_aliyun_sms(&configured, &message).await
        }
        RecoveryChannel::Phone
            if configured.sms_enabled
                && configured.sms_provider == "webhook"
                && configured.sms_webhook_url.starts_with("https://") =>
        {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(12))
                .build()
                .map_err(|_| ApiError::Internal)?;
            let mut request = client.post(configured.sms_webhook_url).json(&message);
            if !configured.sms_webhook_token.is_empty() {
                request = request.bearer_auth(configured.sms_webhook_token);
            }
            let response = request
                .send()
                .await
                .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(ApiError::RecoveryDeliveryFailed)
            }
        }
        _ => state.recovery_delivery.deliver(message).await,
    }
}

async fn load_dynamic_recovery_settings(
    state: &AppState,
) -> Result<DynamicRecoverySettings, ApiError> {
    let Some(settings_key) = state.settings_key.as_deref() else {
        return Ok(DynamicRecoverySettings::default());
    };
    Ok(DynamicRecoverySettings {
        smtp_enabled: read_service_setting(state, "smtp_enabled")
            .await?
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true")),
        smtp_host: read_service_setting(state, "smtp_host")
            .await?
            .unwrap_or_default(),
        smtp_port: read_service_setting(state, "smtp_port")
            .await?
            .and_then(|value| value.parse().ok())
            .unwrap_or(587),
        smtp_username: read_service_setting(state, "smtp_username")
            .await?
            .unwrap_or_default(),
        smtp_password: read_secret_service_setting(state, settings_key, "smtp_password")
            .await?
            .unwrap_or_default(),
        smtp_from: read_service_setting(state, "smtp_from")
            .await?
            .unwrap_or_default(),
        smtp_starttls: read_service_setting(state, "smtp_starttls")
            .await?
            .is_none_or(|value| value == "1" || value.eq_ignore_ascii_case("true")),
        sms_enabled: read_service_setting(state, "sms_enabled")
            .await?
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true")),
        sms_provider: read_service_setting(state, "sms_provider")
            .await?
            .unwrap_or_else(|| "aliyun".to_owned()),
        sms_webhook_url: read_service_setting(state, "sms_webhook_url")
            .await?
            .unwrap_or_default(),
        sms_webhook_token: read_secret_service_setting(state, settings_key, "sms_webhook_token")
            .await?
            .unwrap_or_default(),
        aliyun_sms_access_key_id: read_secret_service_setting(
            state,
            settings_key,
            "aliyun_sms_access_key_id",
        )
        .await?
        .unwrap_or_default(),
        aliyun_sms_access_key_secret: read_secret_service_setting(
            state,
            settings_key,
            "aliyun_sms_access_key_secret",
        )
        .await?
        .unwrap_or_default(),
        aliyun_sms_sign_name: read_service_setting(state, "aliyun_sms_sign_name")
            .await?
            .unwrap_or_default(),
        aliyun_sms_template_code: read_service_setting(state, "aliyun_sms_template_code")
            .await?
            .unwrap_or_default(),
    })
}

async fn deliver_aliyun_sms(
    configured: &DynamicRecoverySettings,
    message: &RecoveryMessage,
) -> Result<(), ApiError> {
    if configured.aliyun_sms_access_key_id.is_empty()
        || configured.aliyun_sms_access_key_secret.is_empty()
        || configured.aliyun_sms_sign_name.is_empty()
        || !configured.aliyun_sms_template_code.starts_with("SMS_")
    {
        return Err(ApiError::RecoveryUnavailable);
    }
    let template_param = serde_json::to_string(&serde_json::json!({"code": message.code}))
        .map_err(|_| ApiError::Internal)?;
    let phone_numbers =
        aliyun_phone_number(&message.destination).ok_or(ApiError::RecoveryDeliveryFailed)?;
    let mut parameters = [
        ("PhoneNumbers", phone_numbers.as_str()),
        ("SignName", configured.aliyun_sms_sign_name.as_str()),
        ("TemplateCode", configured.aliyun_sms_template_code.as_str()),
        ("TemplateParam", template_param.as_str()),
    ];
    parameters.sort_by_key(|(key, _)| *key);
    let canonical_query = parameters
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                aliyun_percent_encode(key),
                aliyun_percent_encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let timestamp = aliyun_timestamp();
    let nonce = Uuid::new_v4().simple().to_string();
    let payload_hash = sha256_hex(&[]);
    let canonical_headers = format!(
        "host:{ALIYUN_SMS_HOST}\n\
         x-acs-action:SendSms\n\
         x-acs-content-sha256:{payload_hash}\n\
         x-acs-date:{timestamp}\n\
         x-acs-signature-nonce:{nonce}\n\
         x-acs-version:2017-05-25\n"
    );
    let signed_headers =
        "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";
    let canonical_request = format!(
        "POST\n/\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let string_to_sign = format!(
        "ACS3-HMAC-SHA256\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = hmac::Key::new(
        hmac::HMAC_SHA256,
        configured.aliyun_sms_access_key_secret.as_bytes(),
    );
    let signature = hex_lower(hmac::sign(&signing_key, string_to_sign.as_bytes()).as_ref());
    let authorization = format!(
        "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={signature}",
        configured.aliyun_sms_access_key_id, signed_headers
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| ApiError::Internal)?;
    let response = client
        .post(format!("https://{ALIYUN_SMS_HOST}/?{canonical_query}"))
        .header("host", ALIYUN_SMS_HOST)
        .header("authorization", authorization)
        .header("x-acs-action", "SendSms")
        .header("x-acs-version", "2017-05-25")
        .header("x-acs-signature-nonce", nonce)
        .header("x-acs-date", timestamp)
        .header("x-acs-content-sha256", payload_hash)
        .send()
        .await
        .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
    if !response.status().is_success() {
        return Err(ApiError::RecoveryDeliveryFailed);
    }
    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
    let code = result
        .get("Code")
        .or_else(|| result.get("code"))
        .and_then(serde_json::Value::as_str);
    if code == Some("OK") {
        Ok(())
    } else {
        Err(ApiError::RecoveryDeliveryFailed)
    }
}

fn aliyun_phone_number(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some(mainland) = trimmed.strip_prefix("+86")
        && mainland.len() == 11
        && mainland.bytes().all(|value| value.is_ascii_digit())
        && mainland.starts_with('1')
    {
        return Some(mainland.to_owned());
    }
    None
}

fn aliyun_timestamp() -> String {
    let value = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

fn aliyun_percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn sha256_hex(value: &[u8]) -> String {
    hex_lower(digest::digest(&digest::SHA256, value).as_ref())
}

fn hex_lower(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

impl RecoveryDelivery {
    fn supports(&self, channel: RecoveryChannel) -> bool {
        match self {
            Self::Disabled => false,
            Self::Webhook {
                email_url, sms_url, ..
            } => match channel {
                RecoveryChannel::Email => email_url.is_some(),
                RecoveryChannel::Phone => sms_url.is_some(),
            },
            #[cfg(test)]
            Self::Capture(_) => true,
        }
    }

    async fn deliver(&self, message: RecoveryMessage) -> Result<(), ApiError> {
        match self {
            Self::Disabled => Err(ApiError::RecoveryUnavailable),
            Self::Webhook {
                email_url,
                sms_url,
                bearer_token,
            } => {
                let url = match message.channel {
                    RecoveryChannel::Email => email_url,
                    RecoveryChannel::Phone => sms_url,
                }
                .as_ref()
                .ok_or(ApiError::RecoveryUnavailable)?;
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(12))
                    .build()
                    .map_err(|_| ApiError::Internal)?;
                let mut request = client.post(url).json(&message);
                if let Some(token) = bearer_token.as_ref().filter(|value| !value.is_empty()) {
                    request = request.bearer_auth(token);
                }
                let response = request
                    .send()
                    .await
                    .map_err(|_| ApiError::RecoveryDeliveryFailed)?;
                if !response.status().is_success() {
                    return Err(ApiError::RecoveryDeliveryFailed);
                }
                Ok(())
            }
            #[cfg(test)]
            Self::Capture(messages) => {
                messages
                    .lock()
                    .map_err(|_| ApiError::Internal)?
                    .push(message);
                Ok(())
            }
        }
    }
}

async fn consume_recovery_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    token: &str,
    purpose: RecoveryPurpose,
) -> Result<String, ApiError> {
    let hash = token_hash(token);
    let row = sqlx::query(
        "SELECT user_id, purpose, expires_at, consumed_at \
         FROM recovery_tokens WHERE token_hash = ?",
    )
    .bind(&hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::InvalidRecovery)?;
    let stored_purpose: String = row.try_get("purpose").map_err(|_| ApiError::Internal)?;
    let expires_at: i64 = row.try_get("expires_at").map_err(|_| ApiError::Internal)?;
    let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(|_| ApiError::Internal)?;
    if stored_purpose != recovery_purpose_to_str(purpose)
        || expires_at <= now()
        || consumed_at.is_some()
    {
        return Err(ApiError::InvalidRecovery);
    }
    let update = sqlx::query(
        "UPDATE recovery_tokens SET consumed_at = ? \
         WHERE token_hash = ? AND consumed_at IS NULL",
    )
    .bind(now())
    .bind(hash)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Internal)?;
    if update.rows_affected() != 1 {
        return Err(ApiError::InvalidRecovery);
    }
    row.try_get("user_id").map_err(|_| ApiError::Internal)
}

fn recovery_destination(
    row: &sqlx::any::AnyRow,
    channel: RecoveryChannel,
) -> Result<String, ApiError> {
    match channel {
        RecoveryChannel::Email => row.try_get("email").map_err(|_| ApiError::Internal),
        RecoveryChannel::Phone => row
            .try_get::<Option<String>, _>("phone")
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::InvalidRecovery),
    }
}

fn mask_destination(destination: &str, channel: RecoveryChannel) -> String {
    match channel {
        RecoveryChannel::Email => {
            let (local, domain) = destination.split_once('@').unwrap_or(("", ""));
            let visible = local.chars().next().unwrap_or('*');
            format!("{visible}***@{domain}")
        }
        RecoveryChannel::Phone => {
            let suffix = destination
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>();
            format!("***{suffix}")
        }
    }
}

fn generate_recovery_code() -> String {
    let mut bytes = [0_u8; 4];
    OsRng.fill_bytes(&mut bytes);
    format!("{:06}", u32::from_le_bytes(bytes) % 1_000_000)
}

fn generate_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn recovery_code_hash(pepper: &str, challenge_id: Uuid, code: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pepper.as_bytes());
    hasher.update(&[0]);
    hasher.update(challenge_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(code.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn constant_time_text_equals(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn recovery_channel_to_str(channel: RecoveryChannel) -> &'static str {
    match channel {
        RecoveryChannel::Email => "email",
        RecoveryChannel::Phone => "phone",
    }
}

fn recovery_purpose_to_str(purpose: RecoveryPurpose) -> &'static str {
    match purpose {
        RecoveryPurpose::AccountPassword => "account_password",
        RecoveryPurpose::UnlockPassword => "unlock_password",
    }
}

fn str_to_recovery_purpose(value: &str) -> Option<RecoveryPurpose> {
    match value {
        "account_password" => Some(RecoveryPurpose::AccountPassword),
        "unlock_password" => Some(RecoveryPurpose::UnlockPassword),
        _ => None,
    }
}

fn normalize_phone(value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if !trimmed.starts_with('+')
        || trimmed.len() < 9
        || trimmed.len() > 16
        || !trimmed[1..].bytes().all(|value| value.is_ascii_digit())
    {
        return Err(ApiError::Validation(
            "mobile number must use international format, for example +8613800138000",
        ));
    }
    Ok(trimmed.to_owned())
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(ApiError::Validation(
            "password must contain at least 12 characters",
        ));
    }
    Ok(())
}

fn validate_credentials(input: &CredentialsRequest, require_phone: bool) -> Result<(), ApiError> {
    if !input.email.contains('@') || input.email.len() > 254 {
        return Err(ApiError::Validation("enter a valid email address"));
    }
    validate_password(&input.password)?;
    if require_phone {
        normalize_phone(
            input
                .phone
                .as_deref()
                .ok_or(ApiError::Validation("enter a valid mobile number"))?,
        )?;
    }
    Ok(())
}

fn validate_record(record: &CipherRecord) -> Result<(), ApiError> {
    if record.ciphertext.is_empty() || record.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ApiError::Validation("ciphertext size is invalid"));
    }
    if record.data_version == 0 || record.base_revision < 0 {
        return Err(ApiError::Validation("record version is invalid"));
    }
    validate_opaque_envelope(&record.ciphertext)?;
    Ok(())
}

fn validate_opaque_envelope(ciphertext: &str) -> Result<(), ApiError> {
    let value: serde_json::Value = serde_json::from_str(ciphertext)
        .map_err(|_| ApiError::Validation("ciphertext envelope is invalid"))?;
    let object = value
        .as_object()
        .ok_or(ApiError::Validation("ciphertext envelope is invalid"))?;
    if object.len() != 4
        || object.get("v").and_then(serde_json::Value::as_u64) != Some(1)
        || !object.contains_key("kdf")
        || !object.contains_key("cipher")
        || !object.contains_key("wrapped_key")
    {
        return Err(ApiError::Validation("ciphertext envelope is invalid"));
    }
    let kdf = object["kdf"]
        .as_object()
        .ok_or(ApiError::Validation("ciphertext envelope is invalid"))?;
    let cipher = object["cipher"]
        .as_object()
        .ok_or(ApiError::Validation("ciphertext envelope is invalid"))?;
    let wrapped = object["wrapped_key"]
        .as_object()
        .ok_or(ApiError::Validation("ciphertext envelope is invalid"))?;
    if kdf.get("name").and_then(serde_json::Value::as_str) != Some("argon2id")
        || !(1024..=262_144).contains(
            &kdf.get("memory_kib")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        )
        || !(1..=10).contains(
            &kdf.get("iterations")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        )
        || !(1..=8).contains(
            &kdf.get("parallelism")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        )
        || cipher.get("name").and_then(serde_json::Value::as_str) != Some("xchacha20-poly1305")
    {
        return Err(ApiError::Validation("ciphertext envelope is invalid"));
    }
    validate_base64_field(kdf, "salt", 16, 64)?;
    validate_base64_field(cipher, "nonce", 24, 24)?;
    validate_base64_field(cipher, "mac", 16, 16)?;
    validate_base64_field(cipher, "data", 1, MAX_CIPHERTEXT_BYTES)?;
    validate_base64_field(wrapped, "nonce", 24, 24)?;
    validate_base64_field(wrapped, "mac", 16, 16)?;
    validate_base64_field(wrapped, "data", 32, 128)?;
    Ok(())
}

fn validate_base64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ApiError> {
    let encoded = object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(ApiError::Validation("ciphertext envelope is invalid"))?;
    // Dart's base64UrlEncode emits RFC 4648 URL-safe padding while older
    // HeartLink/Rust producers used the unpadded variant. Both are canonical
    // URL-safe encodings of the same inert bytes and must remain compatible.
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .map_err(|_| ApiError::Validation("ciphertext envelope is invalid"))?;
    if !(minimum..=maximum).contains(&decoded.len()) {
        return Err(ApiError::Validation("ciphertext envelope is invalid"));
    }
    Ok(())
}

async fn effective_registration_enabled(state: &AppState) -> Result<bool, ApiError> {
    Ok(read_service_setting(state, "registration_enabled")
        .await?
        .map_or(state.registration_enabled, |value| {
            value == "1" || value.eq_ignore_ascii_case("true")
        }))
}

async fn enforce_storage_quota(
    state: &AppState,
    user_id: Uuid,
    record: &CipherRecord,
) -> Result<(), ApiError> {
    let quota_mib = read_service_setting(state, "per_user_quota_mib")
        .await?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(DEFAULT_USER_QUOTA_BYTES / 1024 / 1024)
        .clamp(16, 4096);
    let size_query = match state.database_kind {
        DatabaseKind::Sqlite => {
            "SELECT COALESCE(SUM(LENGTH(ciphertext)), 0) FROM records WHERE user_id = ? AND deleted = 0"
        }
        DatabaseKind::MySql => {
            "SELECT CAST(COALESCE(SUM(OCTET_LENGTH(ciphertext)), 0) AS SIGNED) FROM records WHERE user_id = ? AND deleted = 0"
        }
    };
    let current_total: i64 = sqlx::query_scalar(size_query)
        .bind(user_id.to_string())
        .fetch_one(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?;
    let previous_query = match state.database_kind {
        DatabaseKind::Sqlite => {
            "SELECT LENGTH(ciphertext) FROM records WHERE user_id = ? AND record_id = ? AND deleted = 0"
        }
        DatabaseKind::MySql => {
            "SELECT CAST(OCTET_LENGTH(ciphertext) AS SIGNED) FROM records WHERE user_id = ? AND record_id = ? AND deleted = 0"
        }
    };
    let previous_size: Option<i64> = sqlx::query_scalar(previous_query)
        .bind(user_id.to_string())
        .bind(record.id.to_string())
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?;
    let projected = current_total - previous_size.unwrap_or(0)
        + if record.deleted {
            0
        } else {
            record.ciphertext.len() as i64
        };
    if projected > quota_mib * 1024 * 1024 {
        return Err(ApiError::StorageQuotaExceeded);
    }
    Ok(())
}

async fn read_service_setting(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    let query = match state.database_kind {
        DatabaseKind::Sqlite => {
            "SELECT setting_value FROM service_settings WHERE setting_key = ? AND is_secret = 0"
        }
        DatabaseKind::MySql => {
            "SELECT CAST(setting_value AS CHAR) FROM service_settings WHERE setting_key = ? AND is_secret = 0"
        }
    };
    sqlx::query_scalar(query)
        .bind(key)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)
}

async fn read_secret_service_setting(
    state: &AppState,
    settings_key: &[u8; 32],
    key: &str,
) -> Result<Option<String>, ApiError> {
    let query = match state.database_kind {
        DatabaseKind::Sqlite => {
            "SELECT setting_value FROM service_settings WHERE setting_key = ? AND is_secret = 1"
        }
        DatabaseKind::MySql => {
            "SELECT CAST(setting_value AS CHAR) FROM service_settings WHERE setting_key = ? AND is_secret = 1"
        }
    };
    let encrypted: Option<String> = sqlx::query_scalar(query)
        .bind(key)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| ApiError::Internal)?;
    encrypted
        .map(|value| {
            admin::decrypt_setting(settings_key, key, &value).map_err(|_| ApiError::Internal)
        })
        .transpose()
}

async fn create_session(pool: &AnyPool, user_id: Uuid) -> Result<SessionResponse, ApiError> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let expires_at = now() + SESSION_LIFETIME_SECONDS;
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now())
        .execute(pool)
        .await
        .map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(token_hash(&token))
    .bind(user_id.to_string())
    .bind(expires_at)
    .bind(now())
    .execute(pool)
    .await
    .map_err(|_| ApiError::Internal)?;
    Ok(SessionResponse {
        token,
        user_id,
        expires_at,
    })
}

fn request_device_id(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get(DEVICE_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn validate_device_control_token(value: &str) -> Result<&str, ApiError> {
    if !(32..=256).contains(&value.len())
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii_graphic())
    {
        return Err(ApiError::Validation("invalid device control token"));
    }
    Ok(value)
}

fn device_control_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(DEVICE_CONTROL_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    validate_device_control_token(value).map_err(|_| ApiError::Unauthorized)
}

async fn authenticate(pool: &AnyPool, headers: &HeaderMap) -> Result<Uuid, ApiError> {
    let token = bearer_token(headers)?;
    let id: Option<String> = sqlx::query_scalar(
        "SELECT s.user_id FROM sessions s \
         WHERE s.token_hash = ? AND s.expires_at > ? \
         AND (s.device_id IS NULL OR EXISTS ( \
             SELECT 1 FROM devices d \
             WHERE d.user_id = s.user_id AND d.id = s.device_id AND d.revoked_at IS NULL \
         ))",
    )
    .bind(token_hash(token))
    .bind(now())
    .fetch_optional(pool)
    .await
    .map_err(|error| internal_error("auth.lookup_session", error))?;
    Uuid::parse_str(&id.ok_or(ApiError::Unauthorized)?)
        .map_err(|error| internal_error("auth.parse_user_id", error))
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or(ApiError::Unauthorized)
}

fn token_hash(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

fn kind_to_str(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::ServerProfile => "server_profile",
        RecordKind::Credential => "credential",
        RecordKind::PrivateKey => "private_key",
        RecordKind::ServerGroup => "server_group",
        RecordKind::Tag => "tag",
        RecordKind::CommandSnippet => "command_snippet",
        RecordKind::Preference => "preference",
    }
}

fn str_to_kind(value: &str) -> Option<RecordKind> {
    match value {
        "server_profile" => Some(RecordKind::ServerProfile),
        "credential" => Some(RecordKind::Credential),
        "private_key" => Some(RecordKind::PrivateKey),
        "server_group" => Some(RecordKind::ServerGroup),
        "tag" => Some(RecordKind::Tag),
        "command_snippet" => Some(RecordKind::CommandSnippet),
        "preference" => Some(RecordKind::Preference),
        _ => None,
    }
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("validation failed")]
    Validation(&'static str),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden(&'static str),
    #[error("conflict")]
    Conflict(&'static str),
    #[error("revision conflict")]
    RevisionConflict(i64),
    #[error("client update required")]
    ClientUpgradeRequired { current: i64, submitted: i64 },
    #[error("registration disabled")]
    RegistrationDisabled,
    #[error("account recovery is unavailable")]
    RecoveryUnavailable,
    #[error("invalid or expired recovery authorization")]
    InvalidRecovery,
    #[error("recovery delivery failed")]
    RecoveryDeliveryFailed,
    #[error("storage quota exceeded")]
    StorageQuotaExceeded,
    #[error("not found")]
    NotFound(&'static str),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Validation(message) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                message.to_owned(),
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid account or session".to_owned(),
            ),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message.to_owned()),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", message.to_owned()),
            Self::RevisionConflict(current) => (
                StatusCode::CONFLICT,
                "revision_conflict",
                format!("record changed; current revision is {current}"),
            ),
            Self::ClientUpgradeRequired { current, submitted } => (
                StatusCode::CONFLICT,
                "client_upgrade_required",
                format!(
                    "update HeartLink before syncing this record; cloud data version is {current}, but this client submitted version {submitted}"
                ),
            ),
            Self::RegistrationDisabled => (
                StatusCode::FORBIDDEN,
                "registration_disabled",
                "account registration is disabled".to_owned(),
            ),
            Self::RecoveryUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "recovery_unavailable",
                "email or SMS recovery delivery is not configured".to_owned(),
            ),
            Self::InvalidRecovery => (
                StatusCode::UNAUTHORIZED,
                "invalid_recovery",
                "verification code or recovery authorization is invalid or expired".to_owned(),
            ),
            Self::RecoveryDeliveryFailed => (
                StatusCode::BAD_GATEWAY,
                "recovery_delivery_failed",
                "the verification message could not be delivered".to_owned(),
            ),
            Self::StorageQuotaExceeded => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "storage_quota_exceeded",
                "the encrypted storage quota for this account was exceeded".to_owned(),
            ),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, "not_found", message.to_owned()),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the service could not complete the request".to_owned(),
            ),
        };
        (
            status,
            Json(ErrorResponse {
                code: code.to_owned(),
                message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use serde_json::json;
    use tower::ServiceExt;

    #[test]
    fn idcn_account_identity_uses_stable_provider_id_and_safe_display() {
        let parsed = parse_idcn_identity(&json!({
            "data": {
                "id": 42,
                "phone": "19500000000",
                "email": "user@example.test",
                "username": "operator",
                "credit": "private-business-field"
            }
        }));
        let parsed = match parsed {
            Some(value) => value,
            None => panic!("valid fixture must parse"),
        };
        assert_eq!(parsed.subject, "42");
        assert_eq!(parsed.display_identifier, "19500000000");
        assert!(!parsed.profile_json.contains("credit"));
    }

    fn test_opaque_ciphertext_with_data(seed: u8, data_bytes: usize) -> String {
        json!({
            "v": 1,
            "kdf": {
                "name": "argon2id",
                "memory_kib": 65536,
                "iterations": 2,
                "parallelism": 1,
                "salt": URL_SAFE.encode([seed; 16])
            },
            "cipher": {
                "name": "xchacha20-poly1305",
                "nonce": URL_SAFE_NO_PAD.encode([seed.wrapping_add(1); 24]),
                "data": URL_SAFE.encode(vec![seed.wrapping_add(2); data_bytes]),
                "mac": URL_SAFE.encode([seed.wrapping_add(3); 16])
            },
            "wrapped_key": {
                "nonce": URL_SAFE_NO_PAD.encode([seed.wrapping_add(4); 24]),
                "data": URL_SAFE.encode([seed.wrapping_add(5); 32]),
                "mac": URL_SAFE.encode([seed.wrapping_add(6); 16])
            }
        })
        .to_string()
    }

    fn test_opaque_ciphertext(seed: u8) -> String {
        test_opaque_ciphertext_with_data(seed, 32)
    }

    fn sync_push_request(
        token: &str,
        record_id: Uuid,
        device_id: Uuid,
        ciphertext: &str,
        data_version: u32,
        base_revision: i64,
    ) -> Result<Request<Body>, axum::http::Error> {
        Request::builder()
            .method("POST")
            .uri("/v1/sync/push")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                json!({
                    "record": {
                        "id": record_id,
                        "kind": "preference",
                        "ciphertext": ciphertext,
                        "data_version": data_version,
                        "base_revision": base_revision,
                        "deleted": false,
                        "device_id": device_id
                    }
                })
                .to_string(),
            ))
    }

    #[tokio::test]
    async fn protected_routes_require_an_application_handshake()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize("sqlite::memory:").await?;
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"me@example.test","password":"a sufficiently long password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let error: ErrorResponse = serde_json::from_slice(&body)?;
        assert_eq!(error.code, "handshake_required");
        Ok(())
    }

    #[tokio::test]
    async fn health_and_registration_work() -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize("sqlite::memory:").await?;
        let service = test_app(state);
        let health = service
            .clone()
            .oneshot(Request::builder().uri("/health").body(Body::empty())?)
            .await?;
        assert_eq!(health.status(), StatusCode::OK);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"me@example.test","phone":"+8613800138000","password":"a sufficiently long password"}"#,
            ))?;
        let response = service.oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let session: SessionResponse = serde_json::from_slice(&body)?;
        assert!(!session.token.is_empty());
        assert!(session.expires_at > now());
        Ok(())
    }

    #[tokio::test]
    async fn account_password_can_be_verified_without_creating_a_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize("sqlite::memory:").await?;
        let service = test_app(state);
        let credentials = r#"{"email":"verify@example.test","phone":"+8613800138099","password":"a sufficiently long password"}"#;
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(credentials))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        let verified = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/verify-password")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"verify@example.test","password":"a sufficiently long password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(verified.status(), StatusCode::NO_CONTENT);

        let rejected = service
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/verify-password")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"verify@example.test","password":"the wrong account password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn sync_data_version_never_downgrades_an_existing_opaque_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize("sqlite::memory:").await?;
        let service = test_app(state.clone());
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"data-version@example.test","phone":"+8613800138010","password":"a sufficiently long password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let session: SessionResponse = serde_json::from_slice(&body)?;
        let device_id = Uuid::new_v4();
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", session.token))
                    .body(Body::from(
                        json!({
                            "device_id": device_id,
                            "name": "version gate workstation",
                            "platform": "windows"
                        })
                        .to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let v2_record_id = Uuid::new_v4();
        let initial_v2_ciphertext = test_opaque_ciphertext(10);
        let response = service
            .clone()
            .oneshot(sync_push_request(
                &session.token,
                v2_record_id,
                device_id,
                &initial_v2_ciphertext,
                2,
                0,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let initial_v2: PushResponse = serde_json::from_slice(&body)?;

        // A stale base revision remains a normal CAS conflict even when the
        // submitting client also uses an older data schema. After pulling the
        // current revision, its retry receives the actionable upgrade error.
        let response = service
            .clone()
            .oneshot(sync_push_request(
                &session.token,
                v2_record_id,
                device_id,
                &test_opaque_ciphertext(20),
                1,
                0,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let error: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(error["code"], "revision_conflict");

        let response = service
            .clone()
            .oneshot(sync_push_request(
                &session.token,
                v2_record_id,
                device_id,
                &test_opaque_ciphertext(30),
                1,
                initial_v2.revision,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let error: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(error["code"], "client_upgrade_required");
        assert!(
            error["message"]
                .as_str()
                .is_some_and(|message| message.contains("update HeartLink"))
        );

        let row = sqlx::query(
            "SELECT ciphertext, data_version, current_revision FROM records WHERE record_id = ?",
        )
        .bind(v2_record_id.to_string())
        .fetch_one(&state.pool)
        .await?;
        assert_eq!(
            row.try_get::<String, _>("ciphertext")?,
            initial_v2_ciphertext
        );
        assert_eq!(row.try_get::<i64, _>("data_version")?, 2);
        assert_eq!(
            row.try_get::<i64, _>("current_revision")?,
            initial_v2.revision
        );

        // Updating a v2 record with another v2 envelope remains legal when its
        // per-record base revision is current.
        let replacement_v2_ciphertext = test_opaque_ciphertext(40);
        let response = service
            .clone()
            .oneshot(sync_push_request(
                &session.token,
                v2_record_id,
                device_id,
                &replacement_v2_ciphertext,
                2,
                initial_v2.revision,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let replacement_v2: PushResponse = serde_json::from_slice(&body)?;
        assert!(replacement_v2.revision > initial_v2.revision);

        // A record created by a v1 client may be upgraded to v2 normally.
        let upgraded_record_id = Uuid::new_v4();
        let response = service
            .clone()
            .oneshot(sync_push_request(
                &session.token,
                upgraded_record_id,
                device_id,
                &test_opaque_ciphertext(50),
                1,
                0,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let initial_v1: PushResponse = serde_json::from_slice(&body)?;

        let upgraded_ciphertext = test_opaque_ciphertext(60);
        let response = service
            .clone()
            .oneshot(sync_push_request(
                &session.token,
                upgraded_record_id,
                device_id,
                &upgraded_ciphertext,
                2,
                initial_v1.revision,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let row = sqlx::query("SELECT ciphertext, data_version FROM records WHERE record_id = ?")
            .bind(upgraded_record_id.to_string())
            .fetch_one(&state.pool)
            .await?;
        assert_eq!(row.try_get::<String, _>("ciphertext")?, upgraded_ciphertext);
        assert_eq!(row.try_get::<i64, _>("data_version")?, 2);
        Ok(())
    }

    #[tokio::test]
    async fn initial_pull_returns_current_state_instead_of_duplicate_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize("sqlite::memory:").await?;
        let service = test_app(state.clone());
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"bootstrap@example.test","phone":"+8613800138011","password":"a sufficiently long password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let session: SessionResponse = serde_json::from_slice(&body)?;
        let device_id = Uuid::new_v4();
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", session.token))
                    .body(Body::from(
                        json!({
                            "device_id": device_id,
                            "name": "bootstrap workstation",
                            "platform": "windows"
                        })
                        .to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let record_id = Uuid::new_v4();
        let mut base_revision = 0;
        let mut latest_ciphertext = String::new();
        for seed in 0_u8..100 {
            latest_ciphertext = test_opaque_ciphertext_with_data(seed, 24 * 1024);
            let response = service
                .clone()
                .oneshot(sync_push_request(
                    &session.token,
                    record_id,
                    device_id,
                    &latest_ciphertext,
                    2,
                    base_revision,
                )?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 64 * 1024).await?;
            base_revision = serde_json::from_slice::<PushResponse>(&body)?.revision;
        }
        let retained_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM revision_events")
            .fetch_one(&state.pool)
            .await?;
        assert_eq!(retained_events, MAX_REVISIONS_PER_USER);
        let historical_ciphertext_bytes: i64 =
            sqlx::query_scalar("SELECT SUM(LENGTH(ciphertext)) FROM revision_events")
                .fetch_one(&state.pool)
                .await?;
        assert!(historical_ciphertext_bytes > 2 * 1024 * 1024);

        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/sync/pull?since=0")
                    .header("authorization", format!("Bearer {}", session.token))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2 * 1024 * 1024).await?;
        let pulled: PullResponse = serde_json::from_slice(&body)?;
        assert_eq!(pulled.records.len(), 1);
        assert_eq!(pulled.records[0].revision, base_revision);
        assert_eq!(pulled.records[0].record.ciphertext, latest_ciphertext);
        assert_eq!(pulled.cursor, base_revision);

        // Non-zero cursors retain the event-stream behavior needed by
        // incremental clients.
        let response = service
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/sync/pull?since={}", base_revision - 1))
                    .header("authorization", format!("Bearer {}", session.token))
                    .body(Body::empty())?,
            )
            .await?;
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let incremental: PullResponse = serde_json::from_slice(&body)?;
        assert_eq!(incremental.records.len(), 1);
        assert_eq!(incremental.records[0].revision, base_revision);
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_device_sync_revoke_and_logout_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize("sqlite::memory:").await?;
        let service = test_app(state);
        let register = Request::builder()
            .method("POST")
            .uri("/v1/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"sync@example.test","phone":"+8613800138001","password":"a sufficiently long password"}"#,
            ))?;
        let response = service.clone().oneshot(register).await?;
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let session: SessionResponse = serde_json::from_slice(&body)?;
        let device_id = Uuid::new_v4();

        let register_device = Request::builder()
            .method("POST")
            .uri("/v1/devices")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::from(
                json!({
                    "device_id": device_id,
                    "name": "test workstation",
                    "platform": "linux"
                })
                .to_string(),
            ))?;
        let response = service.clone().oneshot(register_device).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let opaque_ciphertext = json!({
            "v": 1,
            "kdf": {
                "name": "argon2id",
                "memory_kib": 65536,
                "iterations": 2,
                "parallelism": 1,
                "salt": URL_SAFE.encode([1_u8; 16])
            },
            "cipher": {
                "name": "xchacha20-poly1305",
                "nonce": URL_SAFE_NO_PAD.encode([2_u8; 24]),
                "data": URL_SAFE.encode([3_u8; 32]),
                "mac": URL_SAFE.encode([4_u8; 16])
            },
            "wrapped_key": {
                "nonce": URL_SAFE_NO_PAD.encode([5_u8; 24]),
                "data": URL_SAFE.encode([6_u8; 32]),
                "mac": URL_SAFE.encode([7_u8; 16])
            }
        })
        .to_string();
        let push_body = json!({
            "record": {
                "id": Uuid::new_v4(),
                "kind": "preference",
                "ciphertext": opaque_ciphertext,
                "data_version": 1,
                "base_revision": 0,
                "deleted": false,
                "device_id": device_id
            }
        })
        .to_string();
        let push = Request::builder()
            .method("POST")
            .uri("/v1/sync/push")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::from(push_body.clone()))?;
        let response = service.clone().oneshot(push).await?;
        assert_eq!(response.status(), StatusCode::OK);

        let pull = Request::builder()
            .uri("/v1/sync/pull?since=0")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::empty())?;
        let response = service.clone().oneshot(pull).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let pulled: PullResponse = serde_json::from_slice(&body)?;
        assert_eq!(pulled.records.len(), 1);
        assert_eq!(pulled.records[0].record.ciphertext, opaque_ciphertext);

        let stale_push = Request::builder()
            .method("POST")
            .uri("/v1/sync/push")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::from(push_body.clone()))?;
        let response = service.clone().oneshot(stale_push).await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let list = Request::builder()
            .uri("/v1/devices")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::empty())?;
        let response = service.clone().oneshot(list).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let devices: Vec<DeviceResponse> = serde_json::from_slice(&body)?;
        assert_eq!(devices.len(), 1);
        assert!(!devices[0].revoked);

        let replacement_device_id = Uuid::new_v4();
        let register_replacement = Request::builder()
            .method("POST")
            .uri("/v1/devices")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::from(
                json!({
                    "device_id": replacement_device_id,
                    "name": "test workstation",
                    "platform": "linux"
                })
                .to_string(),
            ))?;
        let response = service.clone().oneshot(register_replacement).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let list = Request::builder()
            .uri("/v1/devices")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::empty())?;
        let response = service.clone().oneshot(list).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let devices: Vec<DeviceResponse> = serde_json::from_slice(&body)?;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, replacement_device_id);

        let revoke_without_password = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/devices/{replacement_device_id}"))
            .header("authorization", format!("Bearer {}", session.token))
            .header(DEVICE_ID_HEADER, replacement_device_id.to_string())
            .body(Body::empty())?;
        let response = service.clone().oneshot(revoke_without_password).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let revoke = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/devices/{replacement_device_id}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", session.token))
            .header(DEVICE_ID_HEADER, replacement_device_id.to_string())
            .body(Body::from(r#"{"password":"a sufficiently long password"}"#))?;
        let response = service.clone().oneshot(revoke).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let list = Request::builder()
            .uri("/v1/devices")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::empty())?;
        let response = service.clone().oneshot(list).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let push = Request::builder()
            .method("POST")
            .uri("/v1/sync/push")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::from(push_body))?;
        let response = service.clone().oneshot(push).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let logout = Request::builder()
            .method("DELETE")
            .uri("/v1/auth/session")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::empty())?;
        let response = service.clone().oneshot(logout).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let list = Request::builder()
            .uri("/v1/devices")
            .header("authorization", format!("Bearer {}", session.token))
            .body(Body::empty())?;
        let response = service.oneshot(list).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn revoking_another_device_requires_the_account_password_and_ends_its_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize("sqlite::memory:").await?;
        let service = test_app(state);
        let credentials = r#"{"email":"devices@example.test","phone":"+8613800138008","password":"a sufficiently long password"}"#;
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(credentials))?,
            )
            .await?;
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let first_session: SessionResponse = serde_json::from_slice(&body)?;
        let first_device = Uuid::new_v4();
        let first_control_token = "first-device-control-token-with-enough-entropy";
        assert_eq!(
            service
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/devices")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {}", first_session.token),)
                        .body(Body::from(
                            json!({
                                "device_id": first_device,
                                "name": "primary workstation",
                                "platform": "windows",
                                "control_token": first_control_token
                            })
                            .to_string(),
                        ))?,
                )
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );

        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"email":"devices@example.test","password":"a sufficiently long password"}"#,
                    ))?,
            )
            .await?;
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let second_session: SessionResponse = serde_json::from_slice(&body)?;
        let second_device = Uuid::new_v4();
        let second_control_token = "second-device-control-token-with-enough-entropy";
        assert_eq!(
            service
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/devices")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {}", second_session.token),)
                        .body(Body::from(
                            json!({
                                "device_id": second_device,
                                "name": "secondary workstation",
                                "platform": "windows",
                                "control_token": second_control_token
                            })
                            .to_string(),
                        ))?,
                )
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );

        let wrong_password = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/devices/{second_device}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", first_session.token))
                    .header(DEVICE_ID_HEADER, first_device.to_string())
                    .body(Body::from(r#"{"password":"wrong password"}"#))?,
            )
            .await?;
        assert_eq!(wrong_password.status(), StatusCode::UNAUTHORIZED);

        let revoked = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/devices/{second_device}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", first_session.token))
                    .header(DEVICE_ID_HEADER, first_device.to_string())
                    .body(Body::from(r#"{"password":"a sufficiently long password"}"#))?,
            )
            .await?;
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

        let wrong_control_token = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/devices/{second_device}/control"))
                    .header(
                        DEVICE_CONTROL_HEADER,
                        "incorrect-device-control-token-with-enough-entropy",
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(wrong_control_token.status(), StatusCode::UNAUTHORIZED);

        let pending_control = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/devices/{second_device}/control"))
                    .header(DEVICE_CONTROL_HEADER, second_control_token)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(pending_control.status(), StatusCode::OK);
        let body = to_bytes(pending_control.into_body(), 64 * 1024).await?;
        let pending: DeviceControlResponse = serde_json::from_slice(&body)?;
        assert!(pending.revoked);
        let Some(command) = pending.command else {
            return Err(std::io::Error::other("revoked device did not receive a command").into());
        };
        assert_eq!(command.action, DeviceControlAction::WipeLocalDataAndLogout);

        let removed_device_session = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/devices")
                    .header("authorization", format!("Bearer {}", second_session.token))
                    .header(DEVICE_ID_HEADER, second_device.to_string())
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(removed_device_session.status(), StatusCode::UNAUTHORIZED);

        let acknowledged = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/devices/{second_device}/control"))
                    .header("content-type", "application/json")
                    .header(DEVICE_CONTROL_HEADER, second_control_token)
                    .body(Body::from(
                        json!({"command_id": command.command_id}).to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(acknowledged.status(), StatusCode::NO_CONTENT);

        let after_acknowledgement = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/devices/{second_device}/control"))
                    .header(DEVICE_CONTROL_HEADER, second_control_token)
                    .body(Body::empty())?,
            )
            .await?;
        let body = to_bytes(after_acknowledgement.into_body(), 64 * 1024).await?;
        let after_ack: DeviceControlResponse = serde_json::from_slice(&body)?;
        assert!(after_ack.revoked);
        assert!(after_ack.command.is_none());

        let surviving_device = service
            .oneshot(
                Request::builder()
                    .uri("/v1/devices")
                    .header("authorization", format!("Bearer {}", first_session.token))
                    .header(DEVICE_ID_HEADER, first_device.to_string())
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(surviving_device.status(), StatusCode::OK);
        let body = to_bytes(surviving_device.into_body(), 64 * 1024).await?;
        let devices: Vec<DeviceResponse> = serde_json::from_slice(&body)?;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, first_device);
        assert!(devices[0].online);
        assert!(devices[0].remote_control_enabled);
        Ok(())
    }

    #[test]
    fn aliyun_sms_normalizes_mainland_numbers_and_canonical_query_values() {
        assert_eq!(
            aliyun_phone_number("+8613800138000"),
            Some("13800138000".to_owned())
        );
        assert_eq!(aliyun_phone_number("+85212345678"), None);
        assert_eq!(aliyun_phone_number("13800138000"), None);
        assert_eq!(
            aliyun_percent_encode(r#"{"code":"123456"}"#),
            "%7B%22code%22%3A%22123456%22%7D"
        );
        assert_eq!(
            aliyun_percent_encode("云端 验证"),
            "%E4%BA%91%E7%AB%AF%20%E9%AA%8C%E8%AF%81"
        );
    }

    #[tokio::test]
    async fn registration_can_be_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let state = initialize_with_config(
            "sqlite::memory:",
            ServerConfig {
                registration_enabled: false,
                ..ServerConfig::default()
            },
        )
        .await?;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"blocked@example.test","phone":"+8613800138002","password":"a sufficiently long password"}"#,
            ))?;
        let response = test_app(state).oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn verification_code_is_required_and_single_use_for_password_reset()
    -> Result<(), Box<dyn std::error::Error>> {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = initialize_with_config(
            "sqlite::memory:",
            ServerConfig {
                registration_enabled: true,
                recovery_pepper: "a-test-only-recovery-pepper-that-is-long-enough".to_owned(),
                recovery_delivery: RecoveryDelivery::Capture(captured.clone()),
                settings_key: None,
                handshake: HandshakeState::development("cloud"),
            },
        )
        .await?;
        let service = test_app(state);
        let register = Request::builder()
            .method("POST")
            .uri("/v1/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"recover@example.test","phone":"+8613800138111","password":"the original account password"}"#,
            ))?;
        assert_eq!(
            service.clone().oneshot(register).await?.status(),
            StatusCode::CREATED
        );

        let start = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/request")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"identifier":"recover@example.test","channel":"email","purpose":"account_password"}"#,
            ))?;
        let response = service.clone().oneshot(start).await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let challenge: RecoveryChallengeResponse = serde_json::from_slice(&body)?;
        let code = {
            let messages = captured
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?;
            messages
                .last()
                .ok_or_else(|| std::io::Error::other("recovery code was not delivered"))?
                .code
                .clone()
        };

        let wrong_code = if code == "000000" { "000001" } else { "000000" };
        let wrong = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"challenge_id": challenge.challenge_id, "code": wrong_code}).to_string(),
            ))?;
        assert_eq!(
            service.clone().oneshot(wrong).await?.status(),
            StatusCode::UNAUTHORIZED
        );

        let verify = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"challenge_id": challenge.challenge_id, "code": code}).to_string(),
            ))?;
        let response = service.clone().oneshot(verify).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let verified: RecoveryVerifiedResponse = serde_json::from_slice(&body)?;

        let reset_body = json!({
            "recovery_token": verified.recovery_token,
            "new_password": "the replacement account password"
        })
        .to_string();
        let reset = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/reset-password")
            .header("content-type", "application/json")
            .body(Body::from(reset_body.clone()))?;
        assert_eq!(
            service.clone().oneshot(reset).await?.status(),
            StatusCode::NO_CONTENT
        );
        let replay = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/reset-password")
            .header("content-type", "application/json")
            .body(Body::from(reset_body))?;
        assert_eq!(
            service.clone().oneshot(replay).await?.status(),
            StatusCode::UNAUTHORIZED
        );

        let login = Request::builder()
            .method("POST")
            .uri("/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"recover@example.test","password":"the replacement account password"}"#,
            ))?;
        assert_eq!(
            service.clone().oneshot(login).await?.status(),
            StatusCode::OK
        );

        let start_unlock = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/request")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"identifier":"+8613800138111","channel":"phone","purpose":"unlock_password"}"#,
            ))?;
        let response = service.clone().oneshot(start_unlock).await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let unlock_challenge: RecoveryChallengeResponse = serde_json::from_slice(&body)?;
        let unlock_code = {
            let messages = captured
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?;
            messages
                .last()
                .ok_or_else(|| std::io::Error::other("unlock code was not delivered"))?
                .code
                .clone()
        };
        let verify_unlock = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "challenge_id": unlock_challenge.challenge_id,
                    "code": unlock_code
                })
                .to_string(),
            ))?;
        let response = service.clone().oneshot(verify_unlock).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let unlock_verified: RecoveryVerifiedResponse = serde_json::from_slice(&body)?;
        assert_eq!(unlock_verified.purpose, RecoveryPurpose::UnlockPassword);

        let authorize_body = json!({"recovery_token": unlock_verified.recovery_token}).to_string();
        let authorize_unlock = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/authorize-unlock-reset")
            .header("content-type", "application/json")
            .body(Body::from(authorize_body.clone()))?;
        assert_eq!(
            service.clone().oneshot(authorize_unlock).await?.status(),
            StatusCode::NO_CONTENT
        );
        let replay_unlock = Request::builder()
            .method("POST")
            .uri("/v1/auth/recovery/authorize-unlock-reset")
            .header("content-type", "application/json")
            .body(Body::from(authorize_body))?;
        assert_eq!(
            service.oneshot(replay_unlock).await?.status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }
}
