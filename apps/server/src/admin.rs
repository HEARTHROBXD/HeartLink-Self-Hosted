//! Private-network administration console.
//!
//! The console intentionally exposes account and synchronization metadata
//! only. Opaque ciphertext, password hashes, session tokens, verification
//! codes, and device secrets never appear in its responses.

use crate::{AppState, DatabaseKind, now};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{
    Form, Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const ADMIN_SESSION_SECONDS: i64 = 8 * 60 * 60;
const MAX_ADMIN_BODY_BYTES: usize = 32 * 1024;

/// Cloneable state for the isolated administration listener.
#[derive(Clone)]
pub struct AdminState {
    app: AppState,
    password: Arc<str>,
    settings_key: Arc<[u8; 32]>,
    sessions: Arc<Mutex<HashMap<String, AdminSession>>>,
}

#[derive(Clone)]
struct AdminSession {
    csrf: String,
    expires_at: i64,
}

impl AdminState {
    /// Creates an admin state from the cloud database, a long random console
    /// password, and a 32-byte key used only for provider-secret encryption.
    pub fn new(app: AppState, password: String, settings_key: [u8; 32]) -> Self {
        Self {
            app,
            password: Arc::from(password),
            settings_key: Arc::new(settings_key),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Builds the private administration web application.
pub fn admin_app(state: AdminState) -> Router {
    let router = Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/api/overview", get(overview))
        .route("/api/users", post(create_user))
        .route("/api/users/{user_id}", delete(delete_user))
        .route("/api/users/{user_id}/details", get(user_details))
        .route("/api/settings", get(read_settings).put(update_settings))
        .route("/api/audit", get(audit));
    router
        .layer(DefaultBodyLimit::max(MAX_ADMIN_BODY_BYTES))
        .with_state(state)
}

async fn index(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_private_address(peer.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(session) = authenticated_session(&state, &headers) else {
        return hardened_html(LOGIN_HTML.to_owned());
    };
    hardened_html(DASHBOARD_HTML.replace("__CSRF__", &session.csrf))
}

#[derive(Deserialize)]
struct LoginInput {
    password: String,
}

async fn login(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(input): Form<LoginInput>,
) -> Response {
    if !is_private_address(peer.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if input.password.len() > 1024
        || !constant_time_equals(input.password.as_bytes(), state.password.as_bytes())
    {
        return hardened_html(
            LOGIN_HTML.replace("<!--ERROR-->", "<p class=\"error\">管理密码错误</p>"),
        );
    }
    let token = random_token();
    let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();
    let csrf = random_token();
    let Ok(mut sessions) = state.sessions.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    sessions.retain(|_, session| session.expires_at > now());
    sessions.insert(
        token_hash,
        AdminSession {
            csrf,
            expires_at: now() + ADMIN_SESSION_SECONDS,
        },
    );
    drop(sessions);
    let secure = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"));
    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_static("/"))],
    )
        .into_response();
    let cookie = format!(
        "heartlink_admin={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ADMIN_SESSION_SECONDS}{}",
        if secure { "; Secure" } else { "" }
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn logout(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !is_private_address(peer.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(token) = cookie_value(&headers, "heartlink_admin")
        && let Ok(mut sessions) = state.sessions.lock()
    {
        sessions.remove(&blake3::hash(token.as_bytes()).to_hex().to_string());
    }
    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_static("/"))],
    )
        .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("heartlink_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
    );
    response
}

#[derive(Serialize)]
struct AdminUser {
    id: String,
    email: String,
    phone: Option<String>,
    created_at: i64,
    trusted_device_count: i64,
    online_device_count: i64,
    revoked_device_count: i64,
    pending_remote_wipe_count: i64,
    active_session_count: i64,
    external_identity_count: i64,
    encrypted_snapshot_count: i64,
    encrypted_bytes: i64,
    last_sync_at: Option<i64>,
}

async fn overview(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminUser>>, AdminError> {
    require_admin(&state, peer, &headers, false)?;
    let aggregate = match state.app.database_kind {
        DatabaseKind::Sqlite => {
            "SELECT u.id, u.email, u.phone, u.created_at, \
             (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS trusted_device_count, \
             (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL AND d.last_seen_at >= ?) AS online_device_count, \
             (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NOT NULL) AS revoked_device_count, \
             (SELECT COUNT(*) FROM device_commands c WHERE c.user_id = u.id AND c.acknowledged_at IS NULL) AS pending_remote_wipe_count, \
             (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ? AND s.device_id IS NOT NULL AND EXISTS (SELECT 1 FROM devices d WHERE d.user_id = s.user_id AND d.id = s.device_id AND d.revoked_at IS NULL)) AS active_session_count, \
             (SELECT COUNT(*) FROM external_identities e WHERE e.user_id = u.id) AS external_identity_count, \
             (SELECT COUNT(*) FROM records r WHERE r.user_id = u.id AND r.deleted = 0) AS encrypted_snapshot_count, \
             (SELECT COALESCE(SUM(LENGTH(r.ciphertext)), 0) FROM records r WHERE r.user_id = u.id AND r.deleted = 0) AS encrypted_bytes, \
             (SELECT MAX(r.updated_at) FROM records r WHERE r.user_id = u.id) AS last_sync_at \
             FROM users u ORDER BY u.created_at DESC LIMIT 5000"
        }
        DatabaseKind::MySql => {
            "SELECT u.id, u.email, u.phone, u.created_at, \
             CAST((SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS SIGNED) AS trusted_device_count, \
             CAST((SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL AND d.last_seen_at >= ?) AS SIGNED) AS online_device_count, \
             CAST((SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NOT NULL) AS SIGNED) AS revoked_device_count, \
             CAST((SELECT COUNT(*) FROM device_commands c WHERE c.user_id = u.id AND c.acknowledged_at IS NULL) AS SIGNED) AS pending_remote_wipe_count, \
             CAST((SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ? AND s.device_id IS NOT NULL AND EXISTS (SELECT 1 FROM devices d WHERE d.user_id = s.user_id AND d.id = s.device_id AND d.revoked_at IS NULL)) AS SIGNED) AS active_session_count, \
             CAST((SELECT COUNT(*) FROM external_identities e WHERE e.user_id = u.id) AS SIGNED) AS external_identity_count, \
             CAST((SELECT COUNT(*) FROM records r WHERE r.user_id = u.id AND r.deleted = 0) AS SIGNED) AS encrypted_snapshot_count, \
             CAST((SELECT COALESCE(SUM(OCTET_LENGTH(r.ciphertext)), 0) FROM records r WHERE r.user_id = u.id AND r.deleted = 0) AS SIGNED) AS encrypted_bytes, \
             (SELECT MAX(r.updated_at) FROM records r WHERE r.user_id = u.id) AS last_sync_at \
             FROM users u ORDER BY u.created_at DESC LIMIT 5000"
        }
    };
    let rows = sqlx::query(aggregate)
        .bind(now() - 90)
        .bind(now())
        .fetch_all(&state.app.pool)
        .await
        .map_err(|_| AdminError::Internal)?;
    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        users.push(AdminUser {
            id: row.try_get("id").map_err(|_| AdminError::Internal)?,
            email: row.try_get("email").map_err(|_| AdminError::Internal)?,
            phone: row.try_get("phone").map_err(|_| AdminError::Internal)?,
            created_at: row
                .try_get("created_at")
                .map_err(|_| AdminError::Internal)?,
            trusted_device_count: row
                .try_get("trusted_device_count")
                .map_err(|_| AdminError::Internal)?,
            online_device_count: row
                .try_get("online_device_count")
                .map_err(|_| AdminError::Internal)?,
            revoked_device_count: row
                .try_get("revoked_device_count")
                .map_err(|_| AdminError::Internal)?,
            pending_remote_wipe_count: row
                .try_get("pending_remote_wipe_count")
                .map_err(|_| AdminError::Internal)?,
            active_session_count: row
                .try_get("active_session_count")
                .map_err(|_| AdminError::Internal)?,
            external_identity_count: row
                .try_get("external_identity_count")
                .map_err(|_| AdminError::Internal)?,
            encrypted_snapshot_count: row
                .try_get("encrypted_snapshot_count")
                .map_err(|_| AdminError::Internal)?,
            encrypted_bytes: row
                .try_get("encrypted_bytes")
                .map_err(|_| AdminError::Internal)?,
            last_sync_at: row
                .try_get("last_sync_at")
                .map_err(|_| AdminError::Internal)?,
        });
    }
    Ok(Json(users))
}

#[derive(Serialize)]
struct AdminDeviceDetail {
    id: String,
    name: String,
    platform: String,
    online: bool,
    revoked: bool,
    remote_control_enabled: bool,
    created_at: i64,
    last_seen_at: i64,
    revoked_at: Option<i64>,
}

#[derive(Serialize)]
struct AdminSessionDetail {
    session_reference: String,
    device_id: Option<String>,
    device_name: Option<String>,
    device_platform: Option<String>,
    created_at: i64,
    expires_at: i64,
}

#[derive(Serialize)]
struct AdminRecordDetail {
    record_id: String,
    kind: String,
    kind_label: &'static str,
    data_version: i64,
    device_id: String,
    revision: i64,
    deleted: bool,
    encrypted_bytes: i64,
    updated_at: i64,
}

#[derive(Serialize)]
struct AdminSyncContentDetail {
    category: &'static str,
    included_data: &'static str,
    default_enabled: bool,
}

#[derive(Serialize)]
struct AdminDeviceCommandDetail {
    command_id: String,
    device_id: String,
    action: String,
    issued_at: i64,
    delivered_at: Option<i64>,
    acknowledged_at: Option<i64>,
}

#[derive(Serialize)]
struct AdminExternalIdentityDetail {
    provider: String,
    display_identifier: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
struct AdminUserDetails {
    devices: Vec<AdminDeviceDetail>,
    sessions: Vec<AdminSessionDetail>,
    device_commands: Vec<AdminDeviceCommandDetail>,
    external_identities: Vec<AdminExternalIdentityDetail>,
    encrypted_snapshots: Vec<AdminRecordDetail>,
    sync_content_catalog: Vec<AdminSyncContentDetail>,
    zero_knowledge_notice: &'static str,
    settings_metadata_notice: &'static str,
}

async fn user_details(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<AdminUserDetails>, AdminError> {
    require_admin(&state, peer, &headers, false)?;
    if Uuid::parse_str(&user_id).is_err() {
        return Err(AdminError::NotFound);
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.app.pool)
        .await
        .map_err(|_| AdminError::Internal)?;
    if exists != 1 {
        return Err(AdminError::NotFound);
    }
    let device_rows = sqlx::query(
        "SELECT id, name, platform, revoked_at, created_at, last_seen_at, control_token_hash \
         FROM devices WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(&user_id)
    .fetch_all(&state.app.pool)
    .await
    .map_err(|_| AdminError::Internal)?;
    let current = now();
    let mut devices = Vec::with_capacity(device_rows.len());
    for row in device_rows {
        let revoked_at: Option<i64> = row
            .try_get("revoked_at")
            .map_err(|_| AdminError::Internal)?;
        let last_seen_at: i64 = row
            .try_get("last_seen_at")
            .map_err(|_| AdminError::Internal)?;
        devices.push(AdminDeviceDetail {
            id: row.try_get("id").map_err(|_| AdminError::Internal)?,
            name: row.try_get("name").map_err(|_| AdminError::Internal)?,
            platform: row.try_get("platform").map_err(|_| AdminError::Internal)?,
            online: revoked_at.is_none() && last_seen_at >= current - 90,
            revoked: revoked_at.is_some(),
            remote_control_enabled: row
                .try_get::<Option<String>, _>("control_token_hash")
                .map_err(|_| AdminError::Internal)?
                .is_some(),
            created_at: row
                .try_get("created_at")
                .map_err(|_| AdminError::Internal)?,
            last_seen_at,
            revoked_at,
        });
    }
    let session_rows = sqlx::query(
        "SELECT SUBSTR(s.token_hash, 1, 12) AS session_reference, \
                s.device_id, d.name AS device_name, d.platform AS device_platform, \
                s.created_at, s.expires_at \
         FROM sessions s LEFT JOIN devices d ON d.user_id = s.user_id AND d.id = s.device_id \
         WHERE s.user_id = ? AND s.expires_at > ? ORDER BY s.created_at DESC",
    )
    .bind(&user_id)
    .bind(current)
    .fetch_all(&state.app.pool)
    .await
    .map_err(|_| AdminError::Internal)?;
    let mut sessions = Vec::with_capacity(session_rows.len());
    for row in session_rows {
        sessions.push(AdminSessionDetail {
            session_reference: row
                .try_get("session_reference")
                .map_err(|_| AdminError::Internal)?,
            device_id: row.try_get("device_id").map_err(|_| AdminError::Internal)?,
            device_name: row
                .try_get("device_name")
                .map_err(|_| AdminError::Internal)?,
            device_platform: row
                .try_get("device_platform")
                .map_err(|_| AdminError::Internal)?,
            created_at: row
                .try_get("created_at")
                .map_err(|_| AdminError::Internal)?,
            expires_at: row
                .try_get("expires_at")
                .map_err(|_| AdminError::Internal)?,
        });
    }
    let command_rows = sqlx::query(
        "SELECT id, device_id, action, issued_at, delivered_at, acknowledged_at \
         FROM device_commands WHERE user_id = ? ORDER BY issued_at DESC LIMIT 500",
    )
    .bind(&user_id)
    .fetch_all(&state.app.pool)
    .await
    .map_err(|_| AdminError::Internal)?;
    let mut device_commands = Vec::with_capacity(command_rows.len());
    for row in command_rows {
        device_commands.push(AdminDeviceCommandDetail {
            command_id: row.try_get("id").map_err(|_| AdminError::Internal)?,
            device_id: row.try_get("device_id").map_err(|_| AdminError::Internal)?,
            action: row.try_get("action").map_err(|_| AdminError::Internal)?,
            issued_at: row.try_get("issued_at").map_err(|_| AdminError::Internal)?,
            delivered_at: row
                .try_get("delivered_at")
                .map_err(|_| AdminError::Internal)?,
            acknowledged_at: row
                .try_get("acknowledged_at")
                .map_err(|_| AdminError::Internal)?,
        });
    }
    let external_rows = sqlx::query(
        "SELECT provider, display_identifier, created_at, updated_at \
         FROM external_identities WHERE user_id = ? ORDER BY created_at, provider",
    )
    .bind(&user_id)
    .fetch_all(&state.app.pool)
    .await
    .map_err(|_| AdminError::Internal)?;
    let mut external_identities = Vec::with_capacity(external_rows.len());
    for row in external_rows {
        external_identities.push(AdminExternalIdentityDetail {
            provider: row.try_get("provider").map_err(|_| AdminError::Internal)?,
            display_identifier: row
                .try_get("display_identifier")
                .map_err(|_| AdminError::Internal)?,
            created_at: row
                .try_get("created_at")
                .map_err(|_| AdminError::Internal)?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|_| AdminError::Internal)?,
        });
    }
    let (length_expression, deleted_expression, data_version_expression) =
        match state.app.database_kind {
            DatabaseKind::Sqlite => ("LENGTH(ciphertext)", "deleted", "data_version"),
            DatabaseKind::MySql => (
                "OCTET_LENGTH(ciphertext)",
                "CAST(deleted AS SIGNED)",
                "CAST(data_version AS SIGNED)",
            ),
        };
    let record_query = format!(
        "SELECT record_id, kind, {data_version_expression} AS data_version, \
         device_id, current_revision, {deleted_expression} AS deleted, \
         {length_expression} AS encrypted_bytes, updated_at \
         FROM records WHERE user_id = ? ORDER BY updated_at DESC"
    );
    let record_rows = sqlx::query(&record_query)
        .bind(&user_id)
        .fetch_all(&state.app.pool)
        .await
        .map_err(|_| AdminError::Internal)?;
    let mut encrypted_snapshots = Vec::with_capacity(record_rows.len());
    for row in record_rows {
        let deleted = row
            .try_get::<i64, _>("deleted")
            .map_err(|_| AdminError::Internal)?
            != 0;
        let kind: String = row.try_get("kind").map_err(|_| AdminError::Internal)?;
        encrypted_snapshots.push(AdminRecordDetail {
            record_id: row.try_get("record_id").map_err(|_| AdminError::Internal)?,
            kind_label: admin_record_kind_label(&kind),
            kind,
            data_version: row
                .try_get("data_version")
                .map_err(|_| AdminError::Internal)?,
            device_id: row.try_get("device_id").map_err(|_| AdminError::Internal)?,
            revision: row
                .try_get("current_revision")
                .map_err(|_| AdminError::Internal)?,
            deleted,
            encrypted_bytes: row
                .try_get("encrypted_bytes")
                .map_err(|_| AdminError::Internal)?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|_| AdminError::Internal)?,
        });
    }
    Ok(Json(AdminUserDetails {
        devices,
        sessions,
        device_commands,
        external_identities,
        encrypted_snapshots,
        sync_content_catalog: admin_sync_content_catalog(),
        zero_knowledge_notice: "云端只保存客户端生成的端到端加密记录。后台不会返回密文正文、密码、私钥、命令内容或设备控制密钥。",
        settings_metadata_notice: "preference 类型是客户端同步快照，可包含用户选中的服务器资料、备忘录、资产、凭据、设置、命令和终端日志。后台只能查看元数据，不能读取或直接修改明文。",
    }))
}

fn admin_sync_content_catalog() -> Vec<AdminSyncContentDetail> {
    vec![
        AdminSyncContentDetail {
            category: "SSH 服务器",
            included_data: "连接资料、分组、标签、隧道、终端设置、凭据与主机指纹",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "Windows 远程桌面",
            included_data: "连接资料与加密密码",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "备忘录",
            included_data: "随对应服务器资料同步的五条加密备忘录",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "资产",
            included_data: "资产地址、端口、备注及客户端加密的账号密码",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "代理服务器",
            included_data: "SOCKS5 / HTTP 代理资料与凭据",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "应用与终端设置",
            included_data: "主题、终端、隐私显示、窗口布局与关闭行为",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "安全设置",
            included_data: "自动锁定、剪贴板策略与可选锁屏密码校验值",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "命令库与历史命令",
            included_data: "命令片段、备注、分组与最多 1000 条历史命令",
            default_enabled: true,
        },
        AdminSyncContentDetail {
            category: "终端输出日志",
            included_data: "用户主动保存的 SSH 会话输出与时间信息",
            default_enabled: false,
        },
    ]
}

fn admin_record_kind_label(kind: &str) -> &'static str {
    match kind {
        "server_profile" => "服务器资料（密文）",
        "credential" => "连接凭据（密文）",
        "private_key" => "私钥（密文）",
        "server_group" => "服务器分组（密文）",
        "tag" => "标签（密文）",
        "command_snippet" => "命令库与历史（密文）",
        "preference" => "客户端同步快照（密文）",
        _ => "未知客户端记录（密文）",
    }
}

#[derive(Deserialize)]
struct AdminCreateUser {
    email: String,
    phone: String,
    password: String,
}

#[derive(Deserialize)]
struct AdminDeleteUser {
    confirm_email: String,
}

#[derive(Serialize)]
struct AdminUserMutation {
    id: String,
    email: String,
}

async fn create_user(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<AdminCreateUser>,
) -> Result<(StatusCode, Json<AdminUserMutation>), AdminError> {
    require_admin(&state, peer, &headers, true)?;
    let email = normalize_admin_email(&input.email)?;
    let phone = normalize_admin_phone(&input.phone)?;
    validate_admin_password(&input.password)?;
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(input.password.as_bytes(), &salt)
        .map_err(|_| AdminError::Internal)?
        .to_string();
    let user_id = Uuid::new_v4().to_string();
    let mut tx = state
        .app
        .pool
        .begin()
        .await
        .map_err(|_| AdminError::Internal)?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&user_id)
    .bind(&email)
    .bind(&phone)
    .bind(password_hash)
    .bind(now())
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            return Err(AdminError::Conflict);
        }
        Err(_) => return Err(AdminError::Internal),
    }
    insert_audit_event(&mut tx, "account.create", &format!("{email} ({user_id})")).await?;
    tx.commit().await.map_err(|_| AdminError::Internal)?;
    Ok((
        StatusCode::CREATED,
        Json(AdminUserMutation { id: user_id, email }),
    ))
}

async fn delete_user(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(input): Json<AdminDeleteUser>,
) -> Result<Json<AdminUserMutation>, AdminError> {
    require_admin(&state, peer, &headers, true)?;
    if Uuid::parse_str(&user_id).is_err() {
        return Err(AdminError::NotFound);
    }
    let mut tx = state
        .app
        .pool
        .begin()
        .await
        .map_err(|_| AdminError::Internal)?;
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AdminError::Internal)?;
    let email = email.ok_or(AdminError::NotFound)?;
    if input.confirm_email.trim().to_lowercase() != email.to_lowercase() {
        return Err(AdminError::Confirmation);
    }
    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdminError::Internal)?;
    if result.rows_affected() != 1 {
        return Err(AdminError::NotFound);
    }
    insert_audit_event(&mut tx, "account.delete", &format!("{email} ({user_id})")).await?;
    tx.commit().await.map_err(|_| AdminError::Internal)?;
    Ok(Json(AdminUserMutation { id: user_id, email }))
}

async fn insert_audit_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    action: &str,
    target: &str,
) -> Result<(), AdminError> {
    sqlx::query(
        "INSERT INTO admin_audit_events (id, action, target, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(action)
    .bind(target)
    .bind(now())
    .execute(&mut **tx)
    .await
    .map_err(|_| AdminError::Internal)?;
    Ok(())
}

fn normalize_admin_email(value: &str) -> Result<String, AdminError> {
    let email = value.trim().to_lowercase();
    let (local, domain) = email.split_once('@').ok_or(AdminError::Validation)?;
    if local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || email.len() > 254
        || email.chars().any(char::is_whitespace)
    {
        return Err(AdminError::Validation);
    }
    Ok(email)
}

fn normalize_admin_phone(value: &str) -> Result<String, AdminError> {
    let phone = value.trim();
    if !phone.starts_with('+')
        || phone.len() < 9
        || phone.len() > 20
        || !phone[1..].chars().all(|value| value.is_ascii_digit())
    {
        return Err(AdminError::Validation);
    }
    Ok(phone.to_owned())
}

fn validate_admin_password(value: &str) -> Result<(), AdminError> {
    if value.len() < 12 || value.len() > 1024 {
        return Err(AdminError::Validation);
    }
    Ok(())
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct AdminSettings {
    registration_enabled: bool,
    smtp_enabled: bool,
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    #[serde(default, skip_serializing)]
    smtp_password: String,
    smtp_password_configured: bool,
    smtp_from: String,
    smtp_starttls: bool,
    sms_enabled: bool,
    sms_webhook_url: String,
    #[serde(default, skip_serializing)]
    sms_webhook_token: String,
    sms_webhook_token_configured: bool,
    sms_provider: String,
    #[serde(skip_serializing)]
    aliyun_sms_access_key_id: String,
    aliyun_sms_access_key_id_configured: bool,
    #[serde(skip_serializing)]
    aliyun_sms_access_key_secret: String,
    aliyun_sms_access_key_secret_configured: bool,
    aliyun_sms_sign_name: String,
    aliyun_sms_template_code: String,
    per_user_quota_mib: u32,
}

async fn read_settings(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<AdminSettings>, AdminError> {
    require_admin(&state, peer, &headers, false)?;
    Ok(Json(load_settings(&state).await?))
}

async fn update_settings(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut input): Json<AdminSettings>,
) -> Result<Json<AdminSettings>, AdminError> {
    require_admin(&state, peer, &headers, true)?;
    if input.smtp_port == 0
        || input.smtp_host.len() > 255
        || input.smtp_username.len() > 254
        || input.smtp_from.len() > 254
        || input.sms_webhook_url.len() > 2048
        || input.aliyun_sms_access_key_id.len() > 256
        || input.aliyun_sms_access_key_secret.len() > 512
        || input.aliyun_sms_sign_name.chars().count() > 12
        || input.aliyun_sms_template_code.len() > 64
        || !(16..=4096).contains(&input.per_user_quota_mib)
    {
        return Err(AdminError::Validation);
    }
    if input.sms_provider.is_empty() {
        input.sms_provider = "aliyun".to_owned();
    }
    if input.sms_provider != "aliyun" && input.sms_provider != "webhook" {
        return Err(AdminError::Validation);
    }
    let existing = load_settings(&state).await?;
    if input.sms_enabled
        && ((input.sms_provider == "webhook" && !input.sms_webhook_url.starts_with("https://"))
            || (input.sms_provider == "aliyun"
                && (input.aliyun_sms_sign_name.trim().is_empty()
                    || !input.aliyun_sms_template_code.starts_with("SMS_")
                    || (input.aliyun_sms_access_key_id.is_empty()
                        && !existing.aliyun_sms_access_key_id_configured)
                    || (input.aliyun_sms_access_key_secret.is_empty()
                        && !existing.aliyun_sms_access_key_secret_configured))))
    {
        return Err(AdminError::Validation);
    }
    write_setting(
        &state,
        "registration_enabled",
        if input.registration_enabled {
            "true"
        } else {
            "false"
        },
        false,
    )
    .await?;
    for (key, value) in [
        ("smtp_enabled", input.smtp_enabled.to_string()),
        ("smtp_host", input.smtp_host.clone()),
        ("smtp_port", input.smtp_port.to_string()),
        ("smtp_username", input.smtp_username.clone()),
        ("smtp_from", input.smtp_from.clone()),
        ("smtp_starttls", input.smtp_starttls.to_string()),
        ("sms_enabled", input.sms_enabled.to_string()),
        ("sms_provider", input.sms_provider.clone()),
        ("sms_webhook_url", input.sms_webhook_url.clone()),
        ("aliyun_sms_sign_name", input.aliyun_sms_sign_name.clone()),
        (
            "aliyun_sms_template_code",
            input.aliyun_sms_template_code.clone(),
        ),
        ("per_user_quota_mib", input.per_user_quota_mib.to_string()),
    ] {
        write_setting(&state, key, &value, false).await?;
    }
    if !input.smtp_password.is_empty() {
        write_setting(&state, "smtp_password", &input.smtp_password, true).await?;
    }
    if !input.sms_webhook_token.is_empty() {
        write_setting(&state, "sms_webhook_token", &input.sms_webhook_token, true).await?;
    }
    if !input.aliyun_sms_access_key_id.is_empty() {
        write_setting(
            &state,
            "aliyun_sms_access_key_id",
            &input.aliyun_sms_access_key_id,
            true,
        )
        .await?;
    }
    if !input.aliyun_sms_access_key_secret.is_empty() {
        write_setting(
            &state,
            "aliyun_sms_access_key_secret",
            &input.aliyun_sms_access_key_secret,
            true,
        )
        .await?;
    }
    sqlx::query(
        "INSERT INTO admin_audit_events (id, action, target, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind("settings.update")
    .bind("cloud")
    .bind(now())
    .execute(&state.app.pool)
    .await
    .map_err(|_| AdminError::Internal)?;
    input.smtp_password.clear();
    input.sms_webhook_token.clear();
    input.aliyun_sms_access_key_id.clear();
    input.aliyun_sms_access_key_secret.clear();
    input.smtp_password_configured =
        existing.smtp_password_configured || input.smtp_password_configured;
    input.sms_webhook_token_configured =
        existing.sms_webhook_token_configured || input.sms_webhook_token_configured;
    input.aliyun_sms_access_key_id_configured =
        existing.aliyun_sms_access_key_id_configured || input.aliyun_sms_access_key_id_configured;
    input.aliyun_sms_access_key_secret_configured = existing
        .aliyun_sms_access_key_secret_configured
        || input.aliyun_sms_access_key_secret_configured;
    Ok(Json(load_settings(&state).await?))
}

#[derive(Serialize)]
struct AuditEvent {
    action: String,
    target: String,
    created_at: i64,
}

async fn audit(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEvent>>, AdminError> {
    require_admin(&state, peer, &headers, false)?;
    let rows = sqlx::query(
        "SELECT action, target, created_at FROM admin_audit_events ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(&state.app.pool)
    .await
    .map_err(|_| AdminError::Internal)?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        events.push(AuditEvent {
            action: row.try_get("action").map_err(|_| AdminError::Internal)?,
            target: row.try_get("target").map_err(|_| AdminError::Internal)?,
            created_at: row
                .try_get("created_at")
                .map_err(|_| AdminError::Internal)?,
        });
    }
    Ok(Json(events))
}

async fn load_settings(state: &AdminState) -> Result<AdminSettings, AdminError> {
    let query = match state.app.database_kind {
        DatabaseKind::Sqlite => {
            "SELECT setting_key, setting_value, is_secret FROM service_settings"
        }
        DatabaseKind::MySql => {
            "SELECT setting_key, setting_value, CAST(is_secret AS SIGNED) AS is_secret FROM service_settings"
        }
    };
    let rows = sqlx::query(query)
        .fetch_all(&state.app.pool)
        .await
        .map_err(|_| AdminError::Internal)?;
    let mut values = HashMap::new();
    for row in rows {
        let key: String = row
            .try_get("setting_key")
            .map_err(|_| AdminError::Internal)?;
        let secret = row
            .try_get::<i64, _>("is_secret")
            .map_err(|_| AdminError::Internal)?
            != 0;
        let raw = match state.app.database_kind {
            DatabaseKind::Sqlite => row
                .try_get::<String, _>("setting_value")
                .map_err(|_| AdminError::Internal)?,
            DatabaseKind::MySql => String::from_utf8(
                row.try_get::<Vec<u8>, _>("setting_value")
                    .map_err(|_| AdminError::Internal)?,
            )
            .map_err(|_| AdminError::Internal)?,
        };
        let value = if secret {
            decrypt_setting(&state.settings_key, &key, &raw).map_err(|_| AdminError::Internal)?
        } else {
            raw
        };
        values.insert(key, value);
    }
    let smtp_password = values.get("smtp_password").cloned().unwrap_or_default();
    let sms_token = values.get("sms_webhook_token").cloned().unwrap_or_default();
    let aliyun_access_key_id = values
        .get("aliyun_sms_access_key_id")
        .cloned()
        .unwrap_or_default();
    let aliyun_access_key_secret = values
        .get("aliyun_sms_access_key_secret")
        .cloned()
        .unwrap_or_default();
    Ok(AdminSettings {
        registration_enabled: setting_bool(
            &values,
            "registration_enabled",
            state.app.registration_enabled,
        ),
        smtp_enabled: setting_bool(&values, "smtp_enabled", false),
        smtp_host: values.get("smtp_host").cloned().unwrap_or_default(),
        smtp_port: setting_number(&values, "smtp_port", 587_u16),
        smtp_username: values.get("smtp_username").cloned().unwrap_or_default(),
        smtp_password: String::new(),
        smtp_password_configured: !smtp_password.is_empty(),
        smtp_from: values.get("smtp_from").cloned().unwrap_or_default(),
        smtp_starttls: setting_bool(&values, "smtp_starttls", true),
        sms_enabled: setting_bool(&values, "sms_enabled", false),
        sms_provider: values
            .get("sms_provider")
            .cloned()
            .unwrap_or_else(|| "aliyun".to_owned()),
        sms_webhook_url: values.get("sms_webhook_url").cloned().unwrap_or_default(),
        sms_webhook_token: String::new(),
        sms_webhook_token_configured: !sms_token.is_empty(),
        aliyun_sms_access_key_id: String::new(),
        aliyun_sms_access_key_id_configured: !aliyun_access_key_id.is_empty(),
        aliyun_sms_access_key_secret: String::new(),
        aliyun_sms_access_key_secret_configured: !aliyun_access_key_secret.is_empty(),
        aliyun_sms_sign_name: values
            .get("aliyun_sms_sign_name")
            .cloned()
            .unwrap_or_default(),
        aliyun_sms_template_code: values
            .get("aliyun_sms_template_code")
            .cloned()
            .unwrap_or_default(),
        per_user_quota_mib: setting_number(&values, "per_user_quota_mib", 64_u32),
    })
}

async fn write_setting(
    state: &AdminState,
    key: &str,
    value: &str,
    secret: bool,
) -> Result<(), AdminError> {
    let stored = if secret {
        encrypt_setting(&state.settings_key, key, value)?
    } else {
        value.to_owned()
    };
    let query = match state.app.database_kind {
        DatabaseKind::Sqlite => {
            "INSERT INTO service_settings (setting_key, setting_value, is_secret, updated_at) VALUES (?, ?, ?, ?) \
             ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, is_secret=excluded.is_secret, updated_at=excluded.updated_at"
        }
        DatabaseKind::MySql => {
            "INSERT INTO service_settings (setting_key, setting_value, is_secret, updated_at) VALUES (?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value), is_secret=VALUES(is_secret), updated_at=VALUES(updated_at)"
        }
    };
    sqlx::query(query)
        .bind(key)
        .bind(stored)
        .bind(secret)
        .bind(now())
        .execute(&state.app.pool)
        .await
        .map_err(|_| AdminError::Internal)?;
    Ok(())
}

fn require_admin(
    state: &AdminState,
    peer: SocketAddr,
    headers: &HeaderMap,
    csrf_required: bool,
) -> Result<AdminSession, AdminError> {
    if !is_private_address(peer.ip()) {
        return Err(AdminError::Forbidden);
    }
    let session = authenticated_session(state, headers).ok_or(AdminError::Unauthorized)?;
    if csrf_required
        && headers
            .get("x-heartlink-csrf")
            .and_then(|value| value.to_str().ok())
            != Some(session.csrf.as_str())
    {
        return Err(AdminError::Forbidden);
    }
    Ok(session)
}

fn authenticated_session(state: &AdminState, headers: &HeaderMap) -> Option<AdminSession> {
    let token = cookie_value(headers, "heartlink_admin")?;
    let hash = blake3::hash(token.as_bytes()).to_hex().to_string();
    let mut sessions = state.sessions.lock().ok()?;
    sessions.retain(|_, session| session.expires_at > now());
    sessions.get(&hash).cloned()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn is_private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_private() || value.is_loopback() || value.is_link_local(),
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unicast_link_local()
                || (value.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn encrypt_setting(key: &[u8; 32], name: &str, value: &str) -> Result<String, AdminError> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| AdminError::Internal)?;
    let key = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut in_out = value.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(name.as_bytes()),
        &mut in_out,
    )
    .map_err(|_| AdminError::Internal)?;
    Ok(format!(
        "v1.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce_bytes),
        URL_SAFE_NO_PAD.encode(in_out)
    ))
}

pub(crate) fn decrypt_setting(key: &[u8; 32], name: &str, value: &str) -> Result<String, ()> {
    let mut parts = value.split('.');
    if parts.next() != Some("v1") {
        return Err(());
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(())?)
        .map_err(|_| ())?;
    let mut ciphertext = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(())?)
        .map_err(|_| ())?;
    if parts.next().is_some() || nonce.len() != 12 {
        return Err(());
    }
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| ())?;
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| ())?;
    let key = LessSafeKey::new(unbound);
    let cleartext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(name.as_bytes()),
            &mut ciphertext,
        )
        .map_err(|_| ())?;
    String::from_utf8(cleartext.to_vec()).map_err(|_| ())
}

fn setting_bool(values: &HashMap<String, String>, key: &str, fallback: bool) -> bool {
    values.get(key).map_or(fallback, |value| {
        value == "1" || value.eq_ignore_ascii_case("true")
    })
}

fn setting_number<T>(values: &HashMap<String, String>, key: &str, fallback: T) -> T
where
    T: std::str::FromStr,
{
    values
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn hardened_html(content: String) -> Response {
    let mut response = Html(content).into_response();
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Debug)]
enum AdminError {
    Unauthorized,
    Forbidden,
    Validation,
    Confirmation,
    Conflict,
    NotFound,
    Internal,
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "需要重新登录管理后台"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "管理请求未通过安全校验"),
            Self::Validation => (StatusCode::BAD_REQUEST, "账号或设置内容不符合要求"),
            Self::Confirmation => (StatusCode::BAD_REQUEST, "确认邮箱与目标账号不一致"),
            Self::Conflict => (StatusCode::CONFLICT, "邮箱或手机号已存在"),
            Self::NotFound => (StatusCode::NOT_FOUND, "账号不存在或已删除"),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "管理服务暂时无法完成请求",
            ),
        };
        (status, Json(serde_json::json!({"message": message}))).into_response()
    }
}

const LOGIN_HTML: &str = include_str!("admin_login.html");
const DASHBOARD_HTML: &str = include_str!("admin_dashboard.html");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialize;
    use argon2::{PasswordHash, PasswordVerifier};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn admin_listener_accepts_only_private_or_local_addresses() {
        assert!(is_private_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_private_address(IpAddr::V4(Ipv4Addr::new(10, 16, 5, 8))));
        assert!(is_private_address(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private_address(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_private_address(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_address(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn provider_secret_encryption_round_trips_and_detects_tampering() {
        let key = [0x5a; 32];
        let encrypted = match encrypt_setting(&key, "smtp_password", "provider-secret") {
            Ok(value) => value,
            Err(error) => panic!("provider secret encryption failed: {error:?}"),
        };
        assert!(!encrypted.contains("provider-secret"));
        assert_eq!(
            decrypt_setting(&key, "smtp_password", &encrypted),
            Ok("provider-secret".to_owned())
        );
        assert!(decrypt_setting(&key, "sms_webhook_token", &encrypted).is_err());

        let mut tampered = encrypted;
        let replacement = if tampered.ends_with('A') { 'B' } else { 'A' };
        let _ = tampered.pop();
        tampered.push(replacement);
        assert!(decrypt_setting(&key, "smtp_password", &tampered).is_err());
    }

    #[test]
    fn provider_secrets_are_never_serialized_to_the_admin_frontend() {
        let settings = AdminSettings {
            smtp_password: "smtp-secret-value".to_owned(),
            sms_webhook_token: "webhook-secret-value".to_owned(),
            aliyun_sms_access_key_id: "aliyun-access-key-id".to_owned(),
            aliyun_sms_access_key_secret: "aliyun-access-key-secret".to_owned(),
            ..AdminSettings::default()
        };
        let serialized = match serde_json::to_string(&settings) {
            Ok(value) => value,
            Err(error) => panic!("admin settings serialization failed: {error}"),
        };
        assert!(!serialized.contains("smtp-secret-value"));
        assert!(!serialized.contains("webhook-secret-value"));
        assert!(!serialized.contains("aliyun-access-key-id"));
        assert!(!serialized.contains("aliyun-access-key-secret"));
    }

    #[test]
    fn admin_sync_catalog_exposes_all_client_categories_without_plaintext() {
        let serialized = match serde_json::to_string(&admin_sync_content_catalog()) {
            Ok(value) => value,
            Err(error) => panic!("admin sync catalog serialization failed: {error}"),
        };
        for expected in [
            "SSH 服务器",
            "Windows 远程桌面",
            "备忘录",
            "资产",
            "代理服务器",
            "应用与终端设置",
            "安全设置",
            "命令库与历史命令",
            "终端输出日志",
        ] {
            assert!(serialized.contains(expected), "missing {expected}");
        }
        assert_eq!(
            admin_record_kind_label("preference"),
            "客户端同步快照（密文）"
        );
        assert!(DASHBOARD_HTML.contains("sync_content_catalog"));
        assert!(!DASHBOARD_HTML.contains("smtp-secret-value"));
    }

    #[test]
    fn managed_account_fields_are_normalized_and_validated() {
        assert!(
            matches!(
                normalize_admin_email("  Owner@Example.Test  "),
                Ok(value) if value == "owner@example.test"
            ),
            "valid email should be normalized"
        );
        assert!(normalize_admin_email("invalid").is_err());
        assert!(
            matches!(
                normalize_admin_phone(" +8613800138000 "),
                Ok(value) if value == "+8613800138000"
            ),
            "valid phone should be normalized"
        );
        assert!(normalize_admin_phone("13800138000").is_err());
        assert!(validate_admin_password("twelve-chars").is_ok());
        assert!(validate_admin_password("too-short").is_err());
    }

    #[tokio::test]
    async fn managed_accounts_are_created_and_deleted_with_audit()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = initialize("sqlite::memory:").await?;
        let state = AdminState::new(app, "admin-password".to_owned(), [7_u8; 32]);
        let token = "test-admin-session";
        let csrf = "test-admin-csrf";
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.insert(
                blake3::hash(token.as_bytes()).to_hex().to_string(),
                AdminSession {
                    csrf: csrf.to_owned(),
                    expires_at: now() + 60,
                },
            );
        } else {
            return Err(std::io::Error::other("admin session lock poisoned").into());
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("heartlink_admin={token}"))?,
        );
        headers.insert("x-heartlink-csrf", HeaderValue::from_static(csrf));
        let peer = ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 42000)));

        let created = create_user(
            State(state.clone()),
            peer,
            headers.clone(),
            Json(AdminCreateUser {
                email: "Managed@Example.Test".to_owned(),
                phone: "+8613800138999".to_owned(),
                password: "a managed password".to_owned(),
            }),
        )
        .await
        .map_err(|error| {
            std::io::Error::other(format!("admin account creation failed: {error:?}"))
        })?;
        assert_eq!(created.0, StatusCode::CREATED);
        assert_eq!(created.1.email, "managed@example.test");
        let stored_hash: String =
            sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
                .bind(&created.1.id)
                .fetch_one(&state.app.pool)
                .await?;
        let parsed = PasswordHash::new(&stored_hash)
            .map_err(|error| std::io::Error::other(format!("invalid stored hash: {error}")))?;
        assert!(
            Argon2::default()
                .verify_password("a managed password".as_bytes(), &parsed)
                .is_ok()
        );

        let rejected = delete_user(
            State(state.clone()),
            peer,
            headers.clone(),
            Path(created.1.id.clone()),
            Json(AdminDeleteUser {
                confirm_email: "wrong@example.test".to_owned(),
            }),
        )
        .await;
        assert!(matches!(rejected, Err(AdminError::Confirmation)));

        let deleted = delete_user(
            State(state.clone()),
            peer,
            headers,
            Path(created.1.id.clone()),
            Json(AdminDeleteUser {
                confirm_email: created.1.email.clone(),
            }),
        )
        .await
        .map_err(|error| {
            std::io::Error::other(format!("admin account deletion failed: {error:?}"))
        })?;
        assert_eq!(deleted.email, "managed@example.test");
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = ?")
            .bind(&created.1.id)
            .fetch_one(&state.app.pool)
            .await?;
        assert_eq!(remaining, 0);
        let actions: Vec<String> =
            sqlx::query_scalar("SELECT action FROM admin_audit_events ORDER BY created_at, action")
                .fetch_all(&state.app.pool)
                .await?;
        assert!(actions.iter().any(|value| value == "account.create"));
        assert!(actions.iter().any(|value| value == "account.delete"));
        Ok(())
    }
}
