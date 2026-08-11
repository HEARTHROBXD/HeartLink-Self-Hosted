#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly INSTALLER_VERSION="1.3.1"
readonly DEFAULT_INSTALL_DIR="/opt/heartlink-cloud"
readonly DEFAULT_REPOSITORY="HEARTHROBXD/HeartLink-Self-Hosted"
readonly DEFAULT_STARTUP_TIMEOUT="180"

COMMAND="install"
INSTALL_DIR="${HEARTLINK_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
REPOSITORY="${HEARTLINK_REPOSITORY:-$DEFAULT_REPOSITORY}"
SOURCE_REF="${HEARTLINK_SOURCE_REF:-main}"
SOURCE_ARCHIVE_URL="${HEARTLINK_SOURCE_ARCHIVE_URL:-https://github.com/$REPOSITORY/archive/$SOURCE_REF.tar.gz}"
PUBLISH_IP="${HEARTLINK_PUBLISH_IP:-0.0.0.0}"
PANEL_PUBLISH_IP="${HEARTLINK_PANEL_PUBLISH_IP:-0.0.0.0}"
STARTUP_TIMEOUT="${HEARTLINK_STARTUP_TIMEOUT:-$DEFAULT_STARTUP_TIMEOUT}"
REPOSITORY_EXPLICIT=0
SOURCE_REF_EXPLICIT=0
SOURCE_ARCHIVE_URL_EXPLICIT=0
SOURCE_ARCHIVE_URL_PERSISTED=0
PUBLISH_IP_EXPLICIT=0
PANEL_PUBLISH_IP_EXPLICIT=0
[[ -v HEARTLINK_REPOSITORY ]] && REPOSITORY_EXPLICIT=1
[[ -v HEARTLINK_SOURCE_REF ]] && SOURCE_REF_EXPLICIT=1
[[ -v HEARTLINK_SOURCE_ARCHIVE_URL ]] && SOURCE_ARCHIVE_URL_EXPLICIT=1
[[ -v HEARTLINK_PUBLISH_IP ]] && PUBLISH_IP_EXPLICIT=1
[[ -v HEARTLINK_PANEL_PUBLISH_IP ]] && PANEL_PUBLISH_IP_EXPLICIT=1
PURGE_DATA=0
INSTALL_OPERATION_ACTIVE=0
PREVIOUS_CURRENT_TARGET=""
PREVIOUS_IMAGE_ID=""

log() { printf '[HeartLink] %s\n' "$*"; }
fail() { printf '[HeartLink] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
HeartLink Self-Hosted installer

Usage:
  sudo bash install.sh [install|upgrade|reinstall|start|stop|status|uninstall] [options]

Options:
  --publish-ip ADDRESS   Bind the client cloud endpoint to this IPv4 address
                         (default: 0.0.0.0).
  --panel-publish-ip ADDRESS
                         Bind the administration panel to this IPv4 address
                         (default: 0.0.0.0).
  --install-dir PATH     Installation root (default: /opt/heartlink-cloud).
  --source-ref REF       Git branch or tag to install (default: main).
  --startup-timeout SEC  Maximum time to wait for both HTTP listeners
                         (default: 180 seconds).
  --purge-data           With uninstall only, permanently remove volumes and files.
  -h, --help             Show this help.

The installer does not configure domains, certificates, or a reverse proxy.
Both services are published by IP. Configure HTTPS separately and proxy to
the selected IP addresses on ports 8787 and 8789.
EOF
}

parse_args() {
  if [[ ${1:-} =~ ^(install|upgrade|reinstall|start|stop|status|uninstall)$ ]]; then
    COMMAND="$1"
    shift
  fi
  while (($#)); do
    case "$1" in
      --publish-ip) PUBLISH_IP="${2:?missing publish IP}"; PUBLISH_IP_EXPLICIT=1; shift 2 ;;
      --panel-publish-ip) PANEL_PUBLISH_IP="${2:?missing panel publish IP}"; PANEL_PUBLISH_IP_EXPLICIT=1; shift 2 ;;
      --install-dir) INSTALL_DIR="${2:?missing install directory}"; shift 2 ;;
      --source-ref) SOURCE_REF="${2:?missing source ref}"; SOURCE_REF_EXPLICIT=1; shift 2 ;;
      --startup-timeout) STARTUP_TIMEOUT="${2:?missing startup timeout}"; shift 2 ;;
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

validate_install_root() {
  [[ "$INSTALL_DIR" == /* ]] || fail "installation directory must be an absolute path"
  [[ ${#INSTALL_DIR} -ge 16 ]] || fail "installation directory is too broad"
  if [[ -e "$INSTALL_DIR" ]]; then
    [[ -d "$INSTALL_DIR" ]] || fail "installation root is not a directory"
    [[ ! -L "$INSTALL_DIR" ]] || fail "installation root must not be a symbolic link"
  fi
}

read_config_value() {
  local key="$1" file="$2"
  [[ -f "$file" ]] || return 1
  awk -v key="$key" '
    index($0, key "=") == 1 {
      print substr($0, length(key) + 2)
      exit
    }
  ' "$file"
}

load_persisted_configuration() {
  local value runtime_env="$INSTALL_DIR/.env"
  local installer_state="$INSTALL_DIR/.heartlink-installer-source"

  if [[ -f "$runtime_env" ]]; then
    if (( ! PUBLISH_IP_EXPLICIT )); then
      value="$(read_config_value HEARTLINK_PUBLISH_IP "$runtime_env" || true)"
      [[ -z "$value" ]] || PUBLISH_IP="$value"
    fi
    if (( ! PANEL_PUBLISH_IP_EXPLICIT )); then
      value="$(read_config_value HEARTLINK_PANEL_PUBLISH_IP "$runtime_env" || true)"
      [[ -z "$value" ]] || PANEL_PUBLISH_IP="$value"
    fi
  fi

  if [[ -f "$installer_state" ]]; then
    if (( ! REPOSITORY_EXPLICIT )); then
      value="$(read_config_value repository "$installer_state" || true)"
      [[ -z "$value" ]] || REPOSITORY="$value"
    fi
    if (( ! SOURCE_REF_EXPLICIT )); then
      value="$(read_config_value source_ref "$installer_state" || true)"
      [[ -z "$value" ]] || SOURCE_REF="$value"
    fi
    if (( ! SOURCE_ARCHIVE_URL_EXPLICIT && ! SOURCE_REF_EXPLICIT )); then
      value="$(read_config_value archive_url "$installer_state" || true)"
      if [[ -n "$value" ]]; then
        SOURCE_ARCHIVE_URL="$value"
        SOURCE_ARCHIVE_URL_PERSISTED=1
      fi
    fi
  fi

  if (( ! SOURCE_ARCHIVE_URL_EXPLICIT && ! SOURCE_ARCHIVE_URL_PERSISTED && SOURCE_REF_EXPLICIT )); then
    SOURCE_ARCHIVE_URL="https://github.com/$REPOSITORY/archive/$SOURCE_REF.tar.gz"
  fi
}

validate_runtime_options() {
  validate_publish_addresses
  [[ "$STARTUP_TIMEOUT" =~ ^[0-9]+$ ]] || fail "startup timeout must be a whole number of seconds"
  ((10#$STARTUP_TIMEOUT >= 1 && 10#$STARTUP_TIMEOUT <= 1800)) || \
    fail "startup timeout must be between 1 and 1800 seconds"
  [[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || \
    fail "repository must use the owner/name form"
  [[ "$SOURCE_REF" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "source ref contains unsupported characters"
  [[ "$SOURCE_ARCHIVE_URL" =~ ^https://[^[:space:]]+$ ]] || \
    fail "source archive URL must be an HTTPS URL without whitespace"
}

write_installer_source() {
  local state="$INSTALL_DIR/.heartlink-installer-source" temporary
  temporary="$(mktemp "$INSTALL_DIR/.heartlink-installer-source.XXXXXX")"
  printf 'repository=%s\nsource_ref=%s\narchive_url=%s\n' \
    "$REPOSITORY" "$SOURCE_REF" "$SOURCE_ARCHIVE_URL" >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$state"
}

has_complete_install() {
  [[ -f "$INSTALL_DIR/.heartlink-install-root" ]]
}

has_partial_install() {
  [[ -f "$INSTALL_DIR/.heartlink-installing" ]]
}

has_uninstalled_state() {
  [[ -f "$INSTALL_DIR/.heartlink-uninstalled" ]]
}

compose_available() {
  command -v docker >/dev/null 2>&1 &&
    docker compose version >/dev/null 2>&1 &&
    [[ -f "$INSTALL_DIR/.env" ]] &&
    [[ -f "$INSTALL_DIR/current/infra/docker/compose.yaml" ]]
}

on_exit() {
  local exit_code=$?
  if ((exit_code != 0 && INSTALL_OPERATION_ACTIVE)); then
    if [[ -n "$PREVIOUS_CURRENT_TARGET" && -d "$PREVIOUS_CURRENT_TARGET" ]]; then
      ln -sfn "$PREVIOUS_CURRENT_TARGET" "$INSTALL_DIR/current.next"
      mv -Tf "$INSTALL_DIR/current.next" "$INSTALL_DIR/current"
      if [[ -n "$PREVIOUS_IMAGE_ID" ]]; then
        if docker image tag "$PREVIOUS_IMAGE_ID" heartlink/self-hosted:local >/dev/null 2>&1; then
          log "The previous container image tag was restored."
        else
          printf '[HeartLink] WARNING: the previous image tag could not be restored.\n' >&2
        fi
      fi
      log "The previous release pointer was restored. Run the stable management script with 'start' to resume it."
    fi
    printf '[HeartLink] Installation did not complete. Your data and secrets were preserved.\n' >&2
    if [[ -f "$INSTALL_DIR/install.sh" ]]; then
      printf '[HeartLink] Fix the reported cause, then run: sudo %s reinstall\n' "$INSTALL_DIR/install.sh" >&2
      printf '[HeartLink] Status and diagnostics: sudo %s status\n' "$INSTALL_DIR/install.sh" >&2
    else
      printf '[HeartLink] Download the installer again and run it with the reinstall command.\n' >&2
    fi
  fi
  exit "$exit_code"
}

trap on_exit EXIT

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

validate_ipv4() {
  local label="$1" value="$2" octet
  [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || \
    fail "$label must be an IPv4 address such as 0.0.0.0, 127.0.0.1 or 192.168.1.20"
  local -a octets
  IFS='.' read -r -a octets <<<"$value"
  for octet in "${octets[@]}"; do
    ((10#$octet <= 255)) || fail "$label contains an invalid IPv4 octet"
  done
}

validate_publish_addresses() {
  validate_ipv4 "--publish-ip" "$PUBLISH_IP"
  validate_ipv4 "--panel-publish-ip" "$PANEL_PUBLISH_IP"
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
    upsert_env HEARTLINK_PUBLISH_IP "$PUBLISH_IP"
    upsert_env HEARTLINK_PANEL_PUBLISH_IP "$PANEL_PUBLISH_IP"
    return
  fi
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
HEARTLINK_PUBLISH_IP=$PUBLISH_IP
HEARTLINK_PANEL_PUBLISH_IP=$PANEL_PUBLISH_IP
TZ=${TZ:-Asia/Shanghai}
EOF
  chmod 0600 "$env_file"
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

download_release() {
  local timestamp release_dir archive
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  release_dir="$(mktemp -d "$INSTALL_DIR/releases/${SOURCE_REF//\//-}-$timestamp-XXXXXX")"
  archive="$(mktemp)"
  log "Downloading $REPOSITORY at $SOURCE_REF"
  curl --proto '=https' --tlsv1.2 -fL \
    "$SOURCE_ARCHIVE_URL" -o "$archive"
  tar -xzf "$archive" --strip-components=1 -C "$release_dir"
  rm -f -- "$archive"
  [[ -f "$release_dir/infra/docker/compose.yaml" ]] || fail "source archive is incomplete"
  [[ -f "$release_dir/install.sh" ]] || fail "source archive does not contain the management installer"
  ln -sfn "$release_dir" "$INSTALL_DIR/current.next"
  mv -Tf "$INSTALL_DIR/current.next" "$INSTALL_DIR/current"
}

install_management_script() {
  local source="$INSTALL_DIR/current/install.sh" temporary
  [[ -f "$source" ]] || fail "the selected release has no install.sh management entry point"
  if LC_ALL=C grep -q $'\r' "$source"; then
    fail "install.sh uses CRLF line endings; refusing to install a broken Linux entry point"
  fi
  chmod 0755 "$source"
  temporary="$(mktemp "$INSTALL_DIR/.install.sh.XXXXXX")"
  install -m 0755 "$source" "$temporary"
  mv -f -- "$temporary" "$INSTALL_DIR/install.sh"
  log "Management command installed at $INSTALL_DIR/install.sh"
}

compose() {
  local args=(--project-name heartlink-cloud --env-file "$INSTALL_DIR/.env" \
    -f "$INSTALL_DIR/current/infra/docker/compose.yaml")
  docker compose "${args[@]}" "$@"
}

probe_ip() {
  local value="$1"
  if [[ "$value" == "0.0.0.0" ]]; then
    printf '127.0.0.1\n'
  else
    printf '%s\n' "$value"
  fi
}

http_status() {
  curl --noproxy '*' --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --max-time 3 "$1" 2>/dev/null || true
}

runtime_is_ready() {
  local mysql_id sync_id cloud_status panel_status cloud_ip panel_ip
  mysql_id="$(compose ps -q mysql 2>/dev/null || true)"
  sync_id="$(compose ps -q sync 2>/dev/null || true)"
  [[ -n "$mysql_id" && -n "$sync_id" ]] || return 1
  [[ "$(docker inspect --format '{{.State.Running}}' "$mysql_id" 2>/dev/null || true)" == "true" ]] || return 1
  [[ "$(docker inspect --format '{{.State.Running}}' "$sync_id" 2>/dev/null || true)" == "true" ]] || return 1

  cloud_ip="$(probe_ip "$PUBLISH_IP")"
  panel_ip="$(probe_ip "$PANEL_PUBLISH_IP")"
  cloud_status="$(http_status "http://$cloud_ip:8787/health")"
  panel_status="$(http_status "http://$panel_ip:8789/")"
  [[ "$cloud_status" == "200" ]] || return 1
  [[ "$panel_status" =~ ^[1-4][0-9][0-9]$ ]] || return 1
}

print_runtime_diagnostics() {
  local service container_id
  printf '\n[HeartLink] Docker Compose state (including stopped containers):\n' >&2
  compose ps --all >&2 || true
  for service in mysql sync; do
    container_id="$(compose ps --all -q "$service" 2>/dev/null || true)"
    if [[ -n "$container_id" ]]; then
      docker inspect --format \
        '{{.Name}}: status={{.State.Status}} running={{.State.Running}} exit={{.State.ExitCode}}{{if .State.Health}} health={{.State.Health.Status}}{{end}} error={{.State.Error}}' \
        "$container_id" >&2 || true
    else
      printf '[HeartLink] %s container was not created.\n' "$service" >&2
    fi
  done
  printf '\n[HeartLink] Recent container logs:\n' >&2
  compose logs --no-color --tail 120 mysql sync >&2 || true
  printf '\n' >&2
}

wait_for_runtime() {
  local deadline=$((SECONDS + 10#$STARTUP_TIMEOUT)) next_notice=$((SECONDS + 15))
  log "Waiting up to $STARTUP_TIMEOUT seconds for ports 8787 and 8789 to become healthy"
  while ((SECONDS <= deadline)); do
    if runtime_is_ready; then
      log "Cloud API health check passed on $(probe_ip "$PUBLISH_IP"):8787"
      log "Administration listener is responding on $(probe_ip "$PANEL_PUBLISH_IP"):8789"
      return 0
    fi
    if ((SECONDS >= next_notice)); then
      log "Services are still starting..."
      next_notice=$((SECONDS + 15))
    fi
    sleep 2
  done
  print_runtime_diagnostics
  fail "HeartLink did not become healthy; installation was not marked complete"
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
  local server_ip cloud_ip panel_ip tunnel
  server_ip="$(server_lan_ip)"
  server_ip="${server_ip:-SERVER_IP}"
  cloud_ip="$PUBLISH_IP"
  panel_ip="$PANEL_PUBLISH_IP"
  [[ "$cloud_ip" != "0.0.0.0" ]] || cloud_ip="$server_ip"
  [[ "$panel_ip" != "0.0.0.0" ]] || panel_ip="$server_ip"
  if [[ "$panel_ip" == "127.0.0.1" ]]; then
    tunnel="ssh -N -L 8789:127.0.0.1:8789 root@$server_ip"
  else
    tunnel="not required; connect to the published panel IP"
  fi
  umask 077
  cat >"$INSTALL_DIR/install-result.txt" <<EOF
HeartLink Self-Hosted
Installer version: $INSTALLER_VERSION
Cloud endpoint: http://$cloud_ip:8787
Administration panel: http://$panel_ip:8789
Administration password: $(<"$INSTALL_DIR/secrets/admin-password.txt")
Cloud identity public key: $(<"$INSTALL_DIR/secrets/cloud-identity-public-key.txt")
Panel SSH tunnel: $tunnel
HTTPS upstreams: http://$cloud_ip:8787 and http://$panel_ip:8789
EOF
  chmod 0600 "$INSTALL_DIR/install-result.txt"
  chown 0:0 "$INSTALL_DIR/install-result.txt"
  printf '\n'
  cat "$INSTALL_DIR/install-result.txt"
  printf '\nThe installer does not manage TLS or domains.\n'
  printf 'Before exposing these ports, configure a firewall and a trusted HTTPS reverse proxy.\n'
}

install_or_upgrade() {
  validate_install_root
  install_prerequisites
  install_docker
  install -d -m 0755 "$INSTALL_DIR"
  install -d -m 0755 "$INSTALL_DIR/releases"
  if [[ -L "$INSTALL_DIR/current" ]]; then
    PREVIOUS_CURRENT_TARGET="$(readlink -f "$INSTALL_DIR/current" || true)"
  fi
  umask 077
  printf 'installer=%s\nstarted=%s\ncommand=%s\n' \
    "$INSTALLER_VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$COMMAND" \
    >"$INSTALL_DIR/.heartlink-installing"
  rm -f -- "$INSTALL_DIR/.heartlink-uninstalled"
  INSTALL_OPERATION_ACTIVE=1
  download_release
  install_management_script
  write_installer_source
  write_initial_secrets
  write_environment
  if [[ -n "$PREVIOUS_CURRENT_TARGET" ]]; then
    PREVIOUS_IMAGE_ID="$(docker image inspect --format '{{.Id}}' heartlink/self-hosted:local 2>/dev/null || true)"
  fi
  log "Building the self-hosted-only image; update distribution code is not compiled"
  compose build sync
  ensure_identity_key
  log "Starting HeartLink Cloud"
  compose up -d --remove-orphans
  wait_for_runtime
  compose ps --all
  write_result
  touch "$INSTALL_DIR/.heartlink-install-root"
  chmod 0600 "$INSTALL_DIR/.heartlink-install-root"
  rm -f -- "$INSTALL_DIR/.heartlink-installing"
  rm -f -- "$INSTALL_DIR/.heartlink-uninstalled"
  INSTALL_OPERATION_ACTIVE=0
  PREVIOUS_CURRENT_TARGET=""
  log "Installation completed successfully"
}

show_status() {
  if has_uninstalled_state && ! has_complete_install && ! has_partial_install; then
    log "State: uninstalled; database volumes, secrets and installation files are preserved"
    log "Run '$INSTALL_DIR/install.sh install' to install again, or use 'uninstall --purge-data' for permanent removal"
    return 0
  fi
  if ! has_complete_install && ! has_partial_install; then
    fail "HeartLink is not installed at $INSTALL_DIR"
  fi
  if has_partial_install; then
    log "State: incomplete installation (recovery is available with 'reinstall')"
  else
    log "State: installed"
  fi
  if compose_available; then
    if ! compose ps --all; then
      log "Runtime: Docker Compose could not inspect the project"
      print_runtime_diagnostics
      return 1
    fi
    if [[ -s "$INSTALL_DIR/install-result.txt" ]]; then
      log "Install result is stored at $INSTALL_DIR/install-result.txt"
    fi
    log "Management command: $INSTALL_DIR/install.sh"
    if runtime_is_ready; then
      log "Runtime: healthy; ports 8787 and 8789 are responding"
    else
      log "Runtime: unhealthy or still starting"
      print_runtime_diagnostics
      return 1
    fi
  else
    log "Runtime files are incomplete; no Compose service can be inspected yet"
    return 1
  fi
}

start_cloud() {
  if has_uninstalled_state && ! has_complete_install && ! has_partial_install; then
    fail "HeartLink is uninstalled; run the install or reinstall command"
  fi
  if ! has_complete_install && ! has_partial_install; then
    fail "HeartLink is not installed at $INSTALL_DIR"
  fi
  compose_available || fail "runtime files are incomplete; run the reinstall command"
  compose up -d --remove-orphans
  wait_for_runtime
  compose ps --all
}

stop_cloud() {
  if has_uninstalled_state && ! has_complete_install && ! has_partial_install; then
    log "HeartLink is already uninstalled; data and installation files remain preserved"
    return 0
  fi
  if ! has_complete_install && ! has_partial_install; then
    fail "HeartLink is not installed at $INSTALL_DIR"
  fi
  if compose_available; then
    compose down --remove-orphans
    log "HeartLink Cloud containers were stopped; data and installation files were preserved"
  else
    log "No complete Compose runtime was found; nothing was stopped"
  fi
}

uninstall_cloud() {
  if ! has_complete_install && ! has_partial_install && ! has_uninstalled_state; then
    fail "refusing to uninstall an unmarked directory"
  fi
  [[ ! -L "$INSTALL_DIR" ]] || fail "installation root must not be a symbolic link"
  if ((PURGE_DATA)); then
    if compose_available; then
      compose down --volumes --remove-orphans
    else
      log "No complete Compose runtime was found; continuing with the explicitly requested purge"
    fi
    local resolved
    resolved="$(realpath -e "$INSTALL_DIR")"
    [[ "$resolved" == "$INSTALL_DIR" && "$resolved" == /* && ${#resolved} -ge 16 ]] || \
      fail "unsafe installation directory; data was not removed"
    [[ -f "$resolved/.heartlink-install-root" || -f "$resolved/.heartlink-installing" || \
      -f "$resolved/.heartlink-uninstalled" ]] || \
      fail "installation marker disappeared"
    rm -rf --one-file-system -- "$resolved"
    log "Containers, named volumes, secrets and installation files were permanently removed"
  else
    if has_uninstalled_state && ! has_complete_install && ! has_partial_install; then
      log "HeartLink is already uninstalled; database volumes, secrets and installation files remain preserved"
      log "Run 'install' to install again, or use --purge-data for permanent removal"
      return 0
    fi
    if compose_available; then
      compose down --remove-orphans
      log "Containers were removed"
    else
      log "No complete Compose runtime was found; no containers were removed"
    fi
    rm -f -- "$INSTALL_DIR/.heartlink-install-root" "$INSTALL_DIR/.heartlink-installing"
    touch "$INSTALL_DIR/.heartlink-uninstalled"
    chmod 0600 "$INSTALL_DIR/.heartlink-uninstalled"
    log "HeartLink was uninstalled; database volumes, secrets and installation files were preserved"
    log "Run 'install' to install again, or use --purge-data for permanent removal"
  fi
}

install_cloud() {
  if has_complete_install; then
    if compose_available && runtime_is_ready; then
      log "HeartLink is already installed and healthy; no changes were made"
      show_status
      return 0
    fi
    log "An installed marker exists but the runtime is not healthy; repairing the installation while preserving data"
  elif has_partial_install; then
    log "Recovering an incomplete installation"
  elif has_uninstalled_state; then
    log "Installing HeartLink again while reusing the preserved database volumes and secrets"
  fi
  install_or_upgrade
}

main() {
  parse_args "$@"
  require_root_linux
  validate_install_root
  load_persisted_configuration
  validate_runtime_options
  case "$COMMAND" in
    install)
      install_cloud
      ;;
    upgrade)
      has_complete_install || fail "install HeartLink first, or use reinstall to recover a failed install"
      install_or_upgrade
      ;;
    reinstall)
      if ! has_complete_install && ! has_partial_install && ! has_uninstalled_state; then
        log "No existing markers were found; performing a fresh installation"
      else
        log "Reinstalling HeartLink while preserving database volumes and secrets"
      fi
      install_or_upgrade
      ;;
    start) start_cloud ;;
    stop) stop_cloud ;;
    status) show_status ;;
    uninstall) uninstall_cloud ;;
  esac
}

if [[ "${HEARTLINK_INSTALLER_LIBRARY:-0}" != "1" ]]; then
  main "$@"
fi
