#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly INSTALLER_VERSION="1.0.0"
readonly DEFAULT_INSTALL_DIR="/opt/heartlink-cloud"
readonly DEFAULT_REPOSITORY="HEARTHROBXD/HeartLink-Self-Hosted"

COMMAND="install"
INSTALL_DIR="${HEARTLINK_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
REPOSITORY="${HEARTLINK_REPOSITORY:-$DEFAULT_REPOSITORY}"
SOURCE_REF="${HEARTLINK_SOURCE_REF:-main}"
CLOUD_DOMAIN="${HEARTLINK_CLOUD_DOMAIN:-}"
PANEL_DOMAIN="${HEARTLINK_PANEL_DOMAIN:-}"
ACME_EMAIL="${HEARTLINK_ACME_EMAIL:-}"
PURGE_DATA=0

log() { printf '[HeartLink] %s\n' "$*"; }
fail() { printf '[HeartLink] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
HeartLink Self-Hosted installer

Usage:
  sudo bash install.sh [install|upgrade|status|uninstall] [options]

Options:
  --cloud-domain DOMAIN  Enable automatic HTTPS for the client cloud endpoint.
  --panel-domain DOMAIN  Enable automatic HTTPS for the administration panel.
  --email EMAIL          ACME certificate notification email.
  --install-dir PATH     Installation root (default: /opt/heartlink-cloud).
  --source-ref REF       Git branch or tag to install (default: main).
  --purge-data           With uninstall only, permanently remove volumes and files.
  -h, --help             Show this help.

Without domains, the cloud is exposed on the server's LAN address and the panel
is bound to 127.0.0.1. Use an SSH tunnel to reach the panel securely.
EOF
}

parse_args() {
  if [[ ${1:-} =~ ^(install|upgrade|status|uninstall)$ ]]; then
    COMMAND="$1"
    shift
  fi
  while (($#)); do
    case "$1" in
      --cloud-domain) CLOUD_DOMAIN="${2:?missing cloud domain}"; shift 2 ;;
      --panel-domain) PANEL_DOMAIN="${2:?missing panel domain}"; shift 2 ;;
      --email) ACME_EMAIL="${2:?missing ACME email}"; shift 2 ;;
      --install-dir) INSTALL_DIR="${2:?missing install directory}"; shift 2 ;;
      --source-ref) SOURCE_REF="${2:?missing source ref}"; shift 2 ;;
      --purge-data) PURGE_DATA=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "unknown argument: $1" ;;
    esac
  done
}

require_root_linux() {
  [[ "$(uname -s)" == "Linux" ]] || fail "this installer supports Linux only"
  [[ ${EUID:-$(id -u)} -eq 0 ]] || fail "run with sudo or as root"
  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) fail "supported architectures are x86_64 and arm64" ;;
  esac
}

install_prerequisites() {
  local missing=()
  for command in curl tar openssl; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
  done
  if ((${#missing[@]})); then
    log "Installing prerequisites: ${missing[*]}"
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl tar openssl
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y ca-certificates curl tar openssl
    elif command -v yum >/dev/null 2>&1; then
      yum install -y ca-certificates curl tar openssl
    elif command -v zypper >/dev/null 2>&1; then
      zypper --non-interactive install ca-certificates curl tar openssl
    elif command -v pacman >/dev/null 2>&1; then
      pacman -Sy --needed --noconfirm ca-certificates curl tar openssl
    else
      fail "install curl, tar and openssl, then run the installer again"
    fi
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    return
  fi
  [[ "${HEARTLINK_SKIP_DOCKER_INSTALL:-0}" != "1" ]] || \
    fail "Docker Engine with the Compose plugin is required"
  log "Installing Docker Engine and the Compose plugin using Docker's official installer"
  local docker_script
  docker_script="$(mktemp)"
  trap 'rm -f -- "${docker_script:-}"' RETURN
  curl --proto '=https' --tlsv1.2 -fsSL https://get.docker.com -o "$docker_script"
  sh "$docker_script"
  rm -f -- "$docker_script"
  trap - RETURN
  docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin installation failed"
}

validate_domains() {
  if [[ -n "$CLOUD_DOMAIN" || -n "$PANEL_DOMAIN" || -n "$ACME_EMAIL" ]]; then
    [[ -n "$CLOUD_DOMAIN" && -n "$PANEL_DOMAIN" && -n "$ACME_EMAIL" ]] || \
      fail "--cloud-domain, --panel-domain and --email must be supplied together"
    [[ "$CLOUD_DOMAIN" != "$PANEL_DOMAIN" ]] || fail "cloud and panel domains must differ"
    [[ "$CLOUD_DOMAIN" != *://* && "$PANEL_DOMAIN" != *://* ]] || \
      fail "provide host names without http:// or https://"
  fi
}

random_secret() {
  openssl rand -base64 "$1" | tr -d '\n=' | tr '/+' '_-'
}

write_initial_secrets() {
  local secrets="$INSTALL_DIR/secrets"
  install -d -m 0700 "$secrets"
  if [[ ! -s "$secrets/admin-password.txt" ]]; then
    random_secret 36 >"$secrets/admin-password.txt"
  fi
  if [[ ! -s "$secrets/admin-settings.key" ]]; then
    openssl rand 32 >"$secrets/admin-settings.key"
  fi
  chmod 0400 "$secrets/admin-password.txt" "$secrets/admin-settings.key"
  chown 10001:10001 "$secrets/admin-password.txt" "$secrets/admin-settings.key"
}

write_environment() {
  local env_file="$INSTALL_DIR/.env"
  if [[ -f "$env_file" ]]; then
    upsert_env HEARTLINK_PUBLISH_IP "$([[ -n "$CLOUD_DOMAIN" ]] && printf '127.0.0.1' || printf '0.0.0.0')"
    upsert_env HEARTLINK_CLOUD_DOMAIN "$CLOUD_DOMAIN"
    upsert_env HEARTLINK_PANEL_DOMAIN "$PANEL_DOMAIN"
    upsert_env HEARTLINK_ACME_EMAIL "$ACME_EMAIL"
    return
  fi
  local cloud_publish_ip="0.0.0.0"
  [[ -z "$CLOUD_DOMAIN" ]] || cloud_publish_ip="127.0.0.1"
  umask 077
  cat >"$env_file" <<EOF
HEARTLINK_DATABASE_NAME=heartlink
HEARTLINK_DATABASE_USER=heartlink
HEARTLINK_DATABASE_PASSWORD=$(random_secret 36)
HEARTLINK_DATABASE_ROOT_PASSWORD=$(random_secret 48)
HEARTLINK_RECOVERY_PEPPER=$(random_secret 48)
HEARTLINK_REGISTRATION_ENABLED=true
HEARTLINK_HANDSHAKE_KEY_PATH=$INSTALL_DIR/secrets/cloud-handshake.key
HEARTLINK_ADMIN_PASSWORD_PATH=$INSTALL_DIR/secrets/admin-password.txt
HEARTLINK_ADMIN_SETTINGS_KEY_PATH=$INSTALL_DIR/secrets/admin-settings.key
HEARTLINK_PUBLISH_IP=$cloud_publish_ip
HEARTLINK_PANEL_PUBLISH_IP=127.0.0.1
HEARTLINK_CLOUD_DOMAIN=$CLOUD_DOMAIN
HEARTLINK_PANEL_DOMAIN=$PANEL_DOMAIN
HEARTLINK_ACME_EMAIL=$ACME_EMAIL
TZ=${TZ:-Asia/Shanghai}
EOF
  chmod 0600 "$env_file"
}

read_env_value() {
  local key="$1" env_file="$INSTALL_DIR/.env"
  [[ -f "$env_file" ]] || return 0
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$env_file"
}

upsert_env() {
  local key="$1" value="$2" env_file="$INSTALL_DIR/.env" temporary
  temporary="$(mktemp "$INSTALL_DIR/.env.XXXXXX")"
  awk -F= -v key="$key" -v value="$value" '
    BEGIN { found=0 }
    $1 == key { print key "=" value; found=1; next }
    { print }
    END { if (!found) print key "=" value }
  ' "$env_file" >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$env_file"
}

load_existing_configuration() {
  [[ -f "$INSTALL_DIR/.env" ]] || return 0
  [[ -n "$CLOUD_DOMAIN" ]] || CLOUD_DOMAIN="$(read_env_value HEARTLINK_CLOUD_DOMAIN)"
  [[ -n "$PANEL_DOMAIN" ]] || PANEL_DOMAIN="$(read_env_value HEARTLINK_PANEL_DOMAIN)"
  [[ -n "$ACME_EMAIL" ]] || ACME_EMAIL="$(read_env_value HEARTLINK_ACME_EMAIL)"
}

download_release() {
  local timestamp release_dir archive
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  release_dir="$INSTALL_DIR/releases/${SOURCE_REF//\//-}-$timestamp"
  archive="$(mktemp)"
  install -d -m 0755 "$release_dir" "$INSTALL_DIR/releases"
  log "Downloading $REPOSITORY at $SOURCE_REF"
  curl --proto '=https' --tlsv1.2 -fL \
    "https://github.com/$REPOSITORY/archive/$SOURCE_REF.tar.gz" -o "$archive"
  tar -xzf "$archive" --strip-components=1 -C "$release_dir"
  rm -f -- "$archive"
  [[ -f "$release_dir/infra/docker/compose.yaml" ]] || fail "source archive is incomplete"
  ln -sfn "$release_dir" "$INSTALL_DIR/current.next"
  mv -Tf "$INSTALL_DIR/current.next" "$INSTALL_DIR/current"
}

compose() {
  local args=(--project-name heartlink-cloud --env-file "$INSTALL_DIR/.env" \
    -f "$INSTALL_DIR/current/infra/docker/compose.yaml")
  if [[ -n "$CLOUD_DOMAIN" ]]; then
    args+=(--profile gateway)
  fi
  docker compose "${args[@]}" "$@"
}

ensure_identity_key() {
  local key="$INSTALL_DIR/secrets/cloud-handshake.key"
  local public_key_file="$INSTALL_DIR/secrets/cloud-identity-public-key.txt"
  if [[ -s "$key" && -s "$public_key_file" ]]; then
    return
  fi
  [[ ! -e "$key" ]] || fail "identity private key exists but its public-key record is missing"
  log "Generating the cloud Ed25519 identity key"
  docker run --rm --user 0:0 \
    -v "$INSTALL_DIR/secrets:/keys" \
    --entrypoint heartlink-server heartlink/self-hosted:local \
    --generate-handshake-key /keys/cloud-handshake.key >"$public_key_file"
  [[ -s "$key" && -s "$public_key_file" ]] || fail "identity key generation failed"
  chmod 0400 "$key"
  chmod 0444 "$public_key_file"
  chown 10001:10001 "$key" "$public_key_file"
}

server_lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

write_result() {
  local lan_ip cloud_url panel_url tunnel
  lan_ip="$(server_lan_ip)"
  lan_ip="${lan_ip:-SERVER_IP}"
  if [[ -n "$CLOUD_DOMAIN" ]]; then
    cloud_url="https://$CLOUD_DOMAIN"
    panel_url="https://$PANEL_DOMAIN"
    tunnel="not required; the panel is protected by HTTPS and its password"
  else
    cloud_url="http://$lan_ip:8787"
    panel_url="http://127.0.0.1:8789"
    tunnel="ssh -N -L 8789:127.0.0.1:8789 root@$lan_ip"
  fi
  umask 077
  cat >"$INSTALL_DIR/install-result.txt" <<EOF
HeartLink Self-Hosted
Installer version: $INSTALLER_VERSION
Cloud endpoint: $cloud_url
Administration panel: $panel_url
Administration password: $(<"$INSTALL_DIR/secrets/admin-password.txt")
Cloud identity public key: $(<"$INSTALL_DIR/secrets/cloud-identity-public-key.txt")
Panel SSH tunnel: $tunnel
EOF
  chmod 0600 "$INSTALL_DIR/install-result.txt"
  printf '\n'
  cat "$INSTALL_DIR/install-result.txt"
  if [[ -z "$CLOUD_DOMAIN" ]]; then
    printf '\nLAN mode uses HTTP and is intended only for a trusted private network.\n'
    printf 'For Internet access, rerun upgrade with both domains and an ACME email.\n'
  fi
}

install_or_upgrade() {
  install_prerequisites
  install_docker
  install -d -m 0755 "$INSTALL_DIR"
  touch "$INSTALL_DIR/.heartlink-install-root"
  chmod 0600 "$INSTALL_DIR/.heartlink-install-root"
  download_release
  write_initial_secrets
  write_environment
  log "Building the self-hosted-only image; update distribution code is not compiled"
  compose build sync
  ensure_identity_key
  log "Starting HeartLink Cloud"
  compose up -d --remove-orphans
  compose ps
  write_result
}

show_status() {
  [[ -f "$INSTALL_DIR/.heartlink-install-root" ]] || fail "HeartLink is not installed at $INSTALL_DIR"
  compose ps
  write_result
}

uninstall_cloud() {
  [[ -f "$INSTALL_DIR/.heartlink-install-root" ]] || fail "refusing to uninstall an unmarked directory"
  [[ ! -L "$INSTALL_DIR" ]] || fail "installation root must not be a symbolic link"
  if ((PURGE_DATA)); then
    compose down --volumes --remove-orphans
    local resolved
    resolved="$(realpath -e "$INSTALL_DIR")"
    [[ "$resolved" == "$INSTALL_DIR" && "$resolved" == /* && ${#resolved} -ge 16 ]] || \
      fail "unsafe installation directory; data was not removed"
    [[ -f "$resolved/.heartlink-install-root" ]] || fail "installation marker disappeared"
    rm -rf --one-file-system -- "$resolved"
    log "Containers, named volumes, secrets and installation files were permanently removed"
  else
    compose down --remove-orphans
    log "Containers were removed; database volumes, secrets and files were preserved"
  fi
}

main() {
  parse_args "$@"
  require_root_linux
  load_existing_configuration
  validate_domains
  case "$COMMAND" in
    install)
      [[ ! -e "$INSTALL_DIR/.heartlink-install-root" ]] || \
        fail "already installed; use the upgrade command"
      install_or_upgrade
      ;;
    upgrade)
      [[ -f "$INSTALL_DIR/.heartlink-install-root" ]] || fail "install HeartLink first"
      install_or_upgrade
      ;;
    status) show_status ;;
    uninstall) uninstall_cloud ;;
  esac
}

main "$@"
