//! HeartLink cloud and update service entry point.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use heartlink_server::{
    RecoveryDelivery, ServerConfig,
    admin::{AdminState, admin_app},
    app,
    handshake::HandshakeState,
    initialize_with_config,
};
use std::{env, net::SocketAddr, path::PathBuf};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .without_time()
        .init();
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) == Some("--generate-handshake-key") {
        let path = arguments
            .get(1)
            .ok_or("provide the private seed file path")?;
        let public_key = HandshakeState::generate_seed_file(path)?;
        println!("{public_key}");
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err("unsupported command-line arguments".into());
    }
    let role = env::var("HEARTLINK_SERVICE_ROLE").unwrap_or_else(|_| "cloud".to_owned());
    if role == "self-hosted" {
        return run_self_hosted().await;
    }
    let default_bind = match role.as_str() {
        "update" => "127.0.0.1:8788",
        "admin" => "127.0.0.1:8789",
        _ => "127.0.0.1:8787",
    };
    let bind: SocketAddr = env::var("HEARTLINK_BIND")
        .or_else(|_| env::var("ASTER_BIND"))
        .unwrap_or_else(|_| default_bind.to_owned())
        .parse()?;
    if role == "admin" {
        let password_file = env::var("HEARTLINK_ADMIN_PASSWORD_FILE")
            .map_err(|_| "set HEARTLINK_ADMIN_PASSWORD_FILE to a server-only password file")?;
        let password = std::fs::read_to_string(password_file)?.trim().to_owned();
        if password.len() < 20 {
            return Err("the HeartLink admin password must contain at least 20 characters".into());
        }
        let settings_key_file = env::var("HEARTLINK_ADMIN_SETTINGS_KEY_FILE")
            .map_err(|_| "set HEARTLINK_ADMIN_SETTINGS_KEY_FILE to a 32-byte key file")?;
        let settings_key = read_settings_key(settings_key_file)?;
        let database_url = database_url_from_env()?;
        let registration_enabled = env::var("HEARTLINK_REGISTRATION_ENABLED")
            .map_or(true, |value| {
                value != "0" && !value.eq_ignore_ascii_case("false")
            });
        let app_state = initialize_with_config(
            &database_url,
            ServerConfig {
                registration_enabled,
                recovery_pepper: String::new(),
                recovery_delivery: RecoveryDelivery::Disabled,
                settings_key: Some(settings_key),
                handshake: HandshakeState::development("admin"),
            },
        )
        .await?;
        let listener = tokio::net::TcpListener::bind(bind).await?;
        tracing::info!(%bind, "HeartLink private admin service listening");
        axum::serve(
            listener,
            admin_app(AdminState::new(app_state, password, settings_key))
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown())
        .await?;
        return Ok(());
    }
    let key_file = env::var("HEARTLINK_HANDSHAKE_KEY_FILE")
        .map(PathBuf::from)
        .map_err(|_| "set HEARTLINK_HANDSHAKE_KEY_FILE to a server-only Ed25519 seed file")?;
    let key_id =
        env::var("HEARTLINK_HANDSHAKE_KEY_ID").unwrap_or_else(|_| "self-hosted-v1".to_owned());
    let handshake = HandshakeState::from_seed_file(role.as_str(), key_id, key_file)?;
    let public_key = handshake.public_key_base64();
    if role != "cloud" {
        return Err(
            "HEARTLINK_SERVICE_ROLE must be cloud, admin, or self-hosted in this edition".into(),
        );
    }
    let database_url = database_url_from_env()?;
    let registration_enabled = env::var("HEARTLINK_REGISTRATION_ENABLED").map_or(true, |value| {
        value != "0" && !value.eq_ignore_ascii_case("false")
    });
    let email_webhook = optional_env("HEARTLINK_RECOVERY_EMAIL_WEBHOOK");
    let sms_webhook = optional_env("HEARTLINK_RECOVERY_SMS_WEBHOOK");
    let recovery_enabled = email_webhook.is_some() || sms_webhook.is_some();
    let settings_key = optional_env("HEARTLINK_ADMIN_SETTINGS_KEY_FILE")
        .map(read_settings_key)
        .transpose()?;
    let recovery_pepper = optional_env("HEARTLINK_RECOVERY_PEPPER").unwrap_or_default();
    if (recovery_enabled || settings_key.is_some()) && recovery_pepper.len() < 32 {
        return Err("HEARTLINK_RECOVERY_PEPPER must contain at least 32 characters".into());
    }
    let recovery_delivery = if recovery_enabled {
        RecoveryDelivery::Webhook {
            email_url: email_webhook,
            sms_url: sms_webhook,
            bearer_token: optional_env("HEARTLINK_RECOVERY_WEBHOOK_TOKEN"),
        }
    } else {
        RecoveryDelivery::Disabled
    };
    let state = initialize_with_config(
        &database_url,
        ServerConfig {
            registration_enabled,
            recovery_pepper,
            recovery_delivery,
            settings_key,
            handshake,
        },
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        registration_enabled,
        handshake_public_key = %public_key,
        "HeartLink cloud service listening"
    );
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn run_self_hosted() -> Result<(), Box<dyn std::error::Error>> {
    let password_file = env::var("HEARTLINK_ADMIN_PASSWORD_FILE")
        .map_err(|_| "set HEARTLINK_ADMIN_PASSWORD_FILE to a server-only password file")?;
    let password = std::fs::read_to_string(password_file)?.trim().to_owned();
    if password.len() < 20 {
        return Err("the HeartLink admin password must contain at least 20 characters".into());
    }
    let settings_key_file = env::var("HEARTLINK_ADMIN_SETTINGS_KEY_FILE")
        .map_err(|_| "set HEARTLINK_ADMIN_SETTINGS_KEY_FILE to a 32-byte key file")?;
    let settings_key = read_settings_key(settings_key_file)?;
    let cloud_key_file = env::var("HEARTLINK_CLOUD_HANDSHAKE_KEY_FILE")
        .map(PathBuf::from)
        .map_err(|_| "set HEARTLINK_CLOUD_HANDSHAKE_KEY_FILE")?;
    let cloud_key_id = env::var("HEARTLINK_CLOUD_HANDSHAKE_KEY_ID")
        .unwrap_or_else(|_| "self-hosted-cloud-v1".to_owned());
    let cloud_handshake = HandshakeState::from_seed_file("cloud", cloud_key_id, cloud_key_file)?;
    let cloud_public_key = cloud_handshake.public_key_base64();

    let database_url = database_url_from_env()?;
    let registration_enabled = env::var("HEARTLINK_REGISTRATION_ENABLED").map_or(true, |value| {
        value != "0" && !value.eq_ignore_ascii_case("false")
    });
    let email_webhook = optional_env("HEARTLINK_RECOVERY_EMAIL_WEBHOOK");
    let sms_webhook = optional_env("HEARTLINK_RECOVERY_SMS_WEBHOOK");
    let recovery_enabled = email_webhook.is_some() || sms_webhook.is_some();
    let recovery_pepper = optional_env("HEARTLINK_RECOVERY_PEPPER").unwrap_or_default();
    if (recovery_enabled || !recovery_pepper.is_empty()) && recovery_pepper.len() < 32 {
        return Err("HEARTLINK_RECOVERY_PEPPER must contain at least 32 characters".into());
    }
    let recovery_delivery = if recovery_enabled {
        RecoveryDelivery::Webhook {
            email_url: email_webhook,
            sms_url: sms_webhook,
            bearer_token: optional_env("HEARTLINK_RECOVERY_WEBHOOK_TOKEN"),
        }
    } else {
        RecoveryDelivery::Disabled
    };
    let app_state = initialize_with_config(
        &database_url,
        ServerConfig {
            registration_enabled,
            recovery_pepper,
            recovery_delivery,
            settings_key: Some(settings_key),
            handshake: cloud_handshake,
        },
    )
    .await?;
    let admin_state = AdminState::new(app_state.clone(), password, settings_key);
    let cloud_bind: SocketAddr = env::var("HEARTLINK_CLOUD_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8787".to_owned())
        .parse()?;
    let admin_bind: SocketAddr = env::var("HEARTLINK_ADMIN_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8789".to_owned())
        .parse()?;
    let cloud_listener = tokio::net::TcpListener::bind(cloud_bind).await?;
    let admin_listener = tokio::net::TcpListener::bind(admin_bind).await?;
    tracing::info!(
        %cloud_bind,
        %admin_bind,
        cloud_handshake_public_key = %cloud_public_key,
        "HeartLink self-hosted cloud and administration console listening"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal = tokio::spawn(async move {
        shutdown().await;
        let _ = shutdown_tx.send(true);
    });
    let cloud = axum::serve(cloud_listener, app(app_state))
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()));
    let admin = axum::serve(
        admin_listener,
        admin_app(admin_state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx));
    let result = tokio::try_join!(cloud, admin);
    signal.abort();
    result?;
    Ok(())
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

fn read_settings_key(
    path: impl AsRef<std::path::Path>,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| "the admin settings key must contain exactly 32 bytes".into());
    }
    let encoded = std::str::from_utf8(&bytes)?.trim();
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    decoded
        .try_into()
        .map_err(|_| "the admin settings key must decode to exactly 32 bytes".into())
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn database_url_from_env() -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(value) =
        env::var("HEARTLINK_DATABASE_URL").or_else(|_| env::var("ASTER_DATABASE_URL"))
    {
        return Ok(value);
    }
    let host = env::var("HEARTLINK_DATABASE_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("HEARTLINK_DATABASE_PORT")
        .unwrap_or_else(|_| "3306".to_owned())
        .parse::<u16>()?;
    let name = env::var("HEARTLINK_DATABASE_NAME").unwrap_or_else(|_| "heartlink".to_owned());
    let user = env::var("HEARTLINK_DATABASE_USER").unwrap_or_else(|_| "heartlink".to_owned());
    let password = env::var("HEARTLINK_DATABASE_PASSWORD").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "set HEARTLINK_DATABASE_PASSWORD or HEARTLINK_DATABASE_URL",
        )
    })?;
    let mut url = Url::parse("mysql://127.0.0.1/")?;
    url.set_host(Some(&host))
        .map_err(|_| "invalid HEARTLINK_DATABASE_HOST")?;
    url.set_port(Some(port))
        .map_err(|_| "invalid HEARTLINK_DATABASE_PORT")?;
    url.set_username(&user)
        .map_err(|_| "invalid HEARTLINK_DATABASE_USER")?;
    url.set_password(Some(&password))
        .map_err(|_| "invalid HEARTLINK_DATABASE_PASSWORD")?;
    url.set_path(&format!("/{name}"));
    Ok(url.to_string())
}

async fn shutdown() {
    if tokio::signal::ctrl_c().await.is_err() {
        tracing::warn!("failed to install shutdown signal handler");
    }
}
