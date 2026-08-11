#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export HEARTLINK_INSTALLER_LIBRARY=1
# shellcheck source=../install.sh
source "$repo_root/install.sh"

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

fail_test() {
  printf 'installer smoke test failed: %s\n' "$*" >&2
  exit 1
}

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
  'HEARTLINK_PANEL_PUBLISH_IP=127.0.0.1' >"$INSTALL_DIR/.env"
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
load_persisted_configuration
[[ "$PUBLISH_IP" == "192.0.2.10" ]] || fail_test "cloud bind address was not preserved"
[[ "$PANEL_PUBLISH_IP" == "127.0.0.1" ]] || fail_test "panel bind address was not preserved"
[[ "$SOURCE_ARCHIVE_URL" == "https://mirror.example.test/heartlink/main.tar.gz" ]] || \
  fail_test "source mirror was not preserved"

INSTALL_DIR="$test_root/integration"
events="$test_root/install-events"
mkdir -p "$INSTALL_DIR"
PREVIOUS_CURRENT_TARGET=""
PREVIOUS_IMAGE_ID=""
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
compose() { printf 'compose:%s\n' "$*" >>"$events"; }
ensure_identity_key() { printf 'identity\n' >>"$events"; }
wait_for_runtime() {
  [[ ! -e "$INSTALL_DIR/.heartlink-install-root" ]] || \
    fail_test "completion marker existed before runtime health verification"
  printf 'health\n' >>"$events"
}
write_result() { printf 'result\n' >>"$events"; }

install_or_upgrade
[[ -f "$INSTALL_DIR/.heartlink-install-root" ]] || fail_test "successful install has no completion marker"
health_line="$(grep -n '^health$' "$events" | cut -d: -f1)"
result_line="$(grep -n '^result$' "$events" | cut -d: -f1)"
[[ "$health_line" -lt "$result_line" ]] || fail_test "result was generated before health verification"

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
