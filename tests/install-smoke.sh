#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export HEARTLINK_INSTALLER_LIBRARY=1
# shellcheck source=../install.sh
source "$repo_root/install.sh"

[[ "$DEFAULT_SERVER_IMAGE" =~ ^ghcr\.io/hearthrobxd/heartlink-self-hosted:1\.4\.0@sha256:[0-9a-f]{64}$ ]] || {
  printf 'installer smoke test failed: default server image is not pinned to the 1.4.0 digest\n' >&2
  exit 1
}
[[ "$DEFAULT_SERVER_IMAGE_MIRROR" =~ ^ghcr\.nju\.edu\.cn/hearthrobxd/heartlink-self-hosted:1\.4\.0@sha256:[0-9a-f]{64}$ ]] || {
  printf 'installer smoke test failed: mainland mirror is not pinned to the 1.4.0 digest\n' >&2
  exit 1
}
[[ "${DEFAULT_SERVER_IMAGE##*@}" == "${DEFAULT_SERVER_IMAGE_MIRROR##*@}" ]] || {
  printf 'installer smoke test failed: primary and mirror image digests differ\n' >&2
  exit 1
}

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

fail_test() {
  printf 'installer smoke test failed: %s\n' "$*" >&2
  exit 1
}

compose_file="$repo_root/infra/docker/compose.yaml"
mysql_service="$(awk '/^  mysql:/{keep=1} /^  sync:/{keep=0} keep' "$compose_file")"
sync_service="$(awk '/^  sync:/{keep=1} /^volumes:/{keep=0} keep' "$compose_file")"
[[ "$mysql_service" == *'      - database'* ]] || fail_test "MySQL left the private database network"
[[ "$mysql_service" != *'      - edge'* ]] || fail_test "MySQL was attached to the published-port network"
[[ "$sync_service" == *'      - database'* && "$sync_service" == *'      - edge'* ]] || \
  fail_test "HeartLink has no routable network for published ports"
grep -A2 '^  database:' "$compose_file" | grep -q 'internal: true' || \
  fail_test "database network is not internal"
grep -A2 '^  edge:' "$compose_file" | grep -q 'driver: bridge' || \
  fail_test "published-port edge network is missing"

INSTALL_DIR="$test_root/heartlink-cloud"
mkdir -p "$INSTALL_DIR/current"
cp "$repo_root/install.sh" "$INSTALL_DIR/current/install.sh"
chmod 0644 "$INSTALL_DIR/current/install.sh"

install_management_script
[[ -x "$INSTALL_DIR/current/install.sh" ]] || fail_test "release installer is not executable"
[[ -x "$INSTALL_DIR/install.sh" ]] || fail_test "stable management script is not executable"
cmp "$repo_root/install.sh" "$INSTALL_DIR/install.sh" || fail_test "stable management script differs"

printf '%s\n' \
  'HEARTLINK_PUBLISH_IP=192.0.2.10' \
  'HEARTLINK_PANEL_PUBLISH_IP=127.0.0.1' \
  'HEARTLINK_SERVER_IMAGE=registry.example.test/heartlink/server:tested@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  'HEARTLINK_MYSQL_IMAGE=registry.example.test/library/mysql:8.4.10' >"$INSTALL_DIR/.env"
REPOSITORY="HEARTHROBXD/HeartLink-Self-Hosted"
SOURCE_REF="main"
SOURCE_ARCHIVE_URL="https://mirror.example.test/heartlink/main.tar.gz"
write_installer_source

PUBLISH_IP="0.0.0.0"
PANEL_PUBLISH_IP="0.0.0.0"
SOURCE_ARCHIVE_URL="https://github.com/HEARTHROBXD/HeartLink-Self-Hosted/archive/main.tar.gz"
PUBLISH_IP_EXPLICIT=0
PANEL_PUBLISH_IP_EXPLICIT=0
SOURCE_ARCHIVE_URL_EXPLICIT=0
SOURCE_ARCHIVE_URL_PERSISTED=0
SOURCE_REF_EXPLICIT=0
SERVER_IMAGE_EXPLICIT=0
MYSQL_IMAGE_EXPLICIT=0
load_persisted_configuration
[[ "$PUBLISH_IP" == "192.0.2.10" ]] || fail_test "cloud bind address was not preserved"
[[ "$PANEL_PUBLISH_IP" == "127.0.0.1" ]] || fail_test "panel bind address was not preserved"
[[ "$SOURCE_ARCHIVE_URL" == "https://mirror.example.test/heartlink/main.tar.gz" ]] || \
  fail_test "source mirror was not preserved"
[[ "$SERVER_IMAGE" == "registry.example.test/heartlink/server:tested@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]] || \
  fail_test "prebuilt server image was not preserved"
[[ "$MYSQL_IMAGE" == "registry.example.test/library/mysql:8.4.10" ]] || \
  fail_test "MySQL image override was not preserved"

INSTALL_DIR="$test_root/integration"
events="$test_root/install-events"
mkdir -p "$INSTALL_DIR"
PREVIOUS_CURRENT_TARGET=""
PREVIOUS_ENV_BACKUP=""
INSTALL_OPERATION_ACTIVE=0
COMMAND="install"
install_prerequisites() { :; }
install_docker() { :; }
download_release() {
  mkdir -p "$INSTALL_DIR/current"
  cp "$repo_root/install.sh" "$INSTALL_DIR/current/install.sh"
  printf 'download\n' >>"$events"
}
write_initial_secrets() { printf 'secrets\n' >>"$events"; }
write_environment() {
  printf 'HEARTLINK_PUBLISH_IP=0.0.0.0\nHEARTLINK_PANEL_PUBLISH_IP=0.0.0.0\n' >"$INSTALL_DIR/.env"
  printf 'environment\n' >>"$events"
}
compose() {
  printf 'compose:%s' "$1" >>"$events"
  shift
  printf ' %s' "$@" >>"$events"
  printf '\n' >>"$events"
}
ensure_identity_key() { printf 'identity\n' >>"$events"; }
wait_for_runtime() {
  [[ ! -e "$INSTALL_DIR/.heartlink-install-root" ]] || \
    fail_test "completion marker existed before runtime health verification"
  printf 'health\n' >>"$events"
}
write_result() { printf 'result\n' >>"$events"; }

install_or_upgrade
[[ -f "$INSTALL_DIR/.heartlink-install-root" ]] || fail_test "successful install has no completion marker"
[[ "$(grep -c '^compose:pull mysql$' "$events")" == "1" ]] || \
  fail_test "MySQL image was not pulled exactly once"
[[ "$(grep -c '^compose:pull sync$' "$events")" == "1" ]] || \
  fail_test "prebuilt HeartLink image was not pulled exactly once"
if grep -q '^compose:build' "$events"; then
  fail_test "installer attempted to compile an image on the user's server"
fi
pull_line="$(grep -n '^compose:pull sync$' "$events" | cut -d: -f1)"
identity_line="$(grep -n '^identity$' "$events" | cut -d: -f1)"
[[ "$pull_line" -lt "$identity_line" ]] || fail_test "identity generation ran before the prebuilt image pull"
health_line="$(grep -n '^health$' "$events" | cut -d: -f1)"
result_line="$(grep -n '^result$' "$events" | cut -d: -f1)"
[[ "$health_line" -lt "$result_line" ]] || fail_test "result was generated before health verification"

INSTALL_DIR="$test_root/mirror-fallback"
mkdir -p "$INSTALL_DIR"
printf 'HEARTLINK_SERVER_IMAGE=%s\n' "$DEFAULT_SERVER_IMAGE" >"$INSTALL_DIR/.env"
SERVER_IMAGE="$DEFAULT_SERVER_IMAGE"
SERVER_IMAGE_EXPLICIT=0
fallback_events="$test_root/fallback-events"
compose() {
  printf 'compose:%s %s image=%s\n' "${1:-}" "${2:-}" "$SERVER_IMAGE" >>"$fallback_events"
  if [[ "${1:-}" == "pull" && "${2:-}" == "sync" && "$SERVER_IMAGE" == "$DEFAULT_SERVER_IMAGE" ]]; then
    return 1
  fi
}

pull_runtime_images
[[ "$SERVER_IMAGE" == "$DEFAULT_SERVER_IMAGE_MIRROR" ]] || \
  fail_test "failed GHCR pull did not select the mainland mirror"
grep -Fxq "HEARTLINK_SERVER_IMAGE=$DEFAULT_SERVER_IMAGE_MIRROR" "$INSTALL_DIR/.env" || \
  fail_test "selected mainland mirror was not persisted"
[[ "$(grep -c '^compose:pull sync ' "$fallback_events")" == "2" ]] || \
  fail_test "HeartLink image did not receive exactly one mirror retry"

explicit_image="registry.example.test/heartlink/server:tested@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
printf 'HEARTLINK_SERVER_IMAGE=%s\n' "$explicit_image" >"$INSTALL_DIR/.env"
SERVER_IMAGE="$explicit_image"
SERVER_IMAGE_EXPLICIT=1
compose() {
  [[ "${1:-}" == "pull" && "${2:-}" == "mysql" ]]
}
if (pull_runtime_images >/dev/null 2>&1); then
  fail_test "failed explicit image override was silently replaced"
fi
grep -Fxq "HEARTLINK_SERVER_IMAGE=$explicit_image" "$INSTALL_DIR/.env" || \
  fail_test "failed explicit image override was modified"

validate_image_reference "server image" "ghcr.io/hearthrobxd/heartlink-self-hosted:1.4.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
if (validate_image_reference "server image" "invalid image reference"); then
  fail_test "invalid image reference was accepted"
fi

PUBLISH_IP="0.0.0.0"
PANEL_PUBLISH_IP="127.0.0.1"
compose() {
  if [[ "$1" == "ps" && "$2" == "-q" && "$3" == "mysql" ]]; then
    printf 'mysql-id\n'
    return
  fi
  if [[ "$1" == "ps" && "$2" == "-q" && "$3" == "sync" ]]; then
    printf 'sync-id\n'
    return
  fi
  return 1
}
docker() {
  [[ "$1" == "inspect" ]] || return 1
  printf 'true\n'
}
http_status() {
  case "$1" in
    http://127.0.0.1:8787/health) printf '200\n' ;;
    http://127.0.0.1:8789/) printf '403\n' ;;
    *) printf '000\n' ;;
  esac
}

runtime_is_ready || fail_test "healthy mocked runtime was rejected"
http_status() { printf '000\n'; }
if runtime_is_ready; then
  fail_test "runtime without HTTP listeners was accepted"
fi

INSTALL_DIR="$test_root/uninstall-state"
mkdir -p "$INSTALL_DIR"
touch "$INSTALL_DIR/.heartlink-install-root"
uninstall_events="$test_root/uninstall-events"
PURGE_DATA=0
compose_available() { return 0; }
compose() { printf 'compose:%s %s\n' "${1:-}" "${2:-}" >>"$uninstall_events"; }

uninstall_cloud
[[ ! -e "$INSTALL_DIR/.heartlink-install-root" ]] || fail_test "normal uninstall preserved the installed marker"
[[ ! -e "$INSTALL_DIR/.heartlink-installing" ]] || fail_test "normal uninstall preserved the partial marker"
[[ -f "$INSTALL_DIR/.heartlink-uninstalled" ]] || fail_test "normal uninstall did not record the preserved-data state"
[[ "$(grep -c '^compose:down --remove-orphans$' "$uninstall_events")" == "1" ]] || \
  fail_test "normal uninstall did not remove containers exactly once"

uninstall_cloud
[[ "$(grep -c '^compose:down --remove-orphans$' "$uninstall_events")" == "1" ]] || \
  fail_test "repeated uninstall was not idempotent"

status_output="$(show_status)"
[[ "$status_output" == *"State: uninstalled"* ]] || fail_test "status did not report the uninstalled state"

install_events="$test_root/reinstall-events"
install_or_upgrade() { printf 'install\n' >>"$install_events"; }
install_cloud
[[ "$(grep -c '^install$' "$install_events")" == "1" ]] || \
  fail_test "install did not recover the preserved-data state"

rm -f -- "$INSTALL_DIR/.heartlink-uninstalled"
touch "$INSTALL_DIR/.heartlink-install-root"
runtime_is_ready() { return 1; }
install_cloud
[[ "$(grep -c '^install$' "$install_events")" == "2" ]] || \
  fail_test "install did not repair a legacy stopped runtime with an installed marker"

runtime_is_ready() { return 0; }
show_status() { printf 'healthy-status\n' >>"$install_events"; }
install_cloud
[[ "$(grep -c '^install$' "$install_events")" == "2" ]] || \
  fail_test "install rebuilt an already healthy installation"
[[ "$(grep -c '^healthy-status$' "$install_events")" == "1" ]] || \
  fail_test "install did not report an already healthy installation"

printf 'installer smoke test passed\n'
