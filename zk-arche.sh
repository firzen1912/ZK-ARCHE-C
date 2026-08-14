#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE_STATE_DIR="/var/lib/iot-auth"
SERVER_STATE_DIR="${BASE_STATE_DIR}/server"
CLIENT_STATE_DIR="${BASE_STATE_DIR}/client"

SERVER_BIN="${PROJECT_ROOT}/c_server"
CLIENT_BIN="${PROJECT_ROOT}/c_client"

SERVER_SK_FILE="${SERVER_STATE_DIR}/server_sk.bin"
SERVER_REGISTRY="${SERVER_STATE_DIR}/registry.bin"
SERVER_REGISTRY_BAK="${SERVER_STATE_DIR}/registry.bak"
SERVER_REPLAY_CACHE="${SERVER_STATE_DIR}/replay_cache.bin"

CLIENT_DEVICE_ROOT="${CLIENT_STATE_DIR}/device_root.bin"
CLIENT_SERVER_PUB="${CLIENT_STATE_DIR}/server_pub.bin"
CLIENT_ROLE_CRED="${CLIENT_STATE_DIR}/role_cred.bin"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  _R='\033[0;31m' _G='\033[0;32m' _Y='\033[0;33m'
  _B='\033[0;34m' _C='\033[0;36m' _W='\033[1;37m' _N='\033[0m'
else
  _R='' _G='' _Y='' _B='' _C='' _W='' _N=''
fi

log_info() { echo -e "${_B}[INFO]${_N}  $*"; }
log_ok() { echo -e "${_G}[OK]${_N}    $*"; }
log_warn() { echo -e "${_Y}[WARN]${_N}  $*"; }
log_error() { echo -e "${_R}[ERROR]${_N} $*" >&2; }
log_header() { echo -e "\n${_W}==> $*${_N}"; }
die() { log_error "$*"; exit 1; }

usage() {
  cat <<EOF

${_W}ZK-ARCHE C helper — current v2 RPK + ZKP flow${_N}

${_C}USAGE${_N}
  ./zk-arche.sh <command> [options]

${_C}BUILD / BOOTSTRAP${_N}
  build
  init-rpk
  pin-server <server_pub_hex>
  show-pinned-key

${_C}STATE${_N}
  check-server-state
  check-client-state
  status
  reset-server
  reset-client
  reset-all

${_C}SERVER${_N}
  start-server <bind_addr> [server options]
  server-local <bind_addr> [--pairing-token TOKEN] [--pairing-seconds N]

${_C}CLIENT${_N}
  setup-device <server_ip:port> [--pairing-token TOKEN] [--allow-tofu-setup]
  auth-device <server_ip:port>
  client-local <server_ip:port> [--pairing-token TOKEN] [--allow-tofu-setup]
  full-device-onboard <server_ip:port> [--pairing-token TOKEN] [--allow-tofu-setup]

EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

require_bin() {
  local bin="$1"
  [[ -x "$bin" ]] || die "Binary not found or not executable: $bin. Run ./zk-arche.sh build first."
}

validate_hex32() {
  [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]] || die "Expected exactly 32 bytes encoded as 64 hexadecimal characters."
}

ensure_state_dirs() {
  sudo install -d -m 700 "$BASE_STATE_DIR" "$SERVER_STATE_DIR" "$CLIENT_STATE_DIR"
}

status_file() {
  local path="$1" label="$2"
  if sudo test -f "$path"; then
    local size
    size="$(sudo wc -c < "$path" | tr -d ' ')"
    log_ok "$label: present (${size}B)"
  else
    log_warn "$label: absent"
  fi
}

cmd_build() {
  require_cmd gcc
  require_cmd pkg-config
  pkg-config --exists libsodium || die "libsodium development files not found (pkg-config libsodium)."
  local sodium_cflags sodium_libs
  sodium_cflags="$(pkg-config --cflags libsodium)"
  sodium_libs="$(pkg-config --libs libsodium)"

  log_header "Building C binaries"
  gcc -O2 -std=c11 -Wall -Wextra -pedantic ${sodium_cflags} "$PROJECT_ROOT/server.c" -o "$SERVER_BIN" ${sodium_libs}
  gcc -O2 -std=c11 -Wall -Wextra -pedantic ${sodium_cflags} "$PROJECT_ROOT/client.c" -o "$CLIENT_BIN" ${sodium_libs}
  log_ok "Server: $SERVER_BIN"
  log_ok "Client: $CLIENT_BIN"
}

cmd_pin_server() {
  [[ $# -eq 1 ]] || die "pin-server requires <server_pub_hex>"
  require_bin "$CLIENT_BIN"
  validate_hex32 "$1"
  ensure_state_dirs
  sudo "$CLIENT_BIN" --pin-server-pub "$1"
  log_ok "Pinned server public key"
}

cmd_show_pinned_key() {
  ensure_state_dirs
  sudo test -f "$CLIENT_SERVER_PUB" || die "Pinned server key not found: $CLIENT_SERVER_PUB"
  sudo od -An -v -tx1 "$CLIENT_SERVER_PUB" | tr -d ' \n'
  echo
}

cmd_init_rpk() {
  require_bin "$SERVER_BIN"
  require_bin "$CLIENT_BIN"
  ensure_state_dirs

  log_header "Initializing RPK bootstrap state"
  local server_pub
  server_pub="$(sudo "$SERVER_BIN" --print-pubkey | tail -n 1 | tr -d '\r\n')"
  validate_hex32 "$server_pub"
  sudo "$CLIENT_BIN" --pin-server-pub "$server_pub"

  log_info "Ensuring client identity exists"
  sudo "$CLIENT_BIN" --print-identity
  log_ok "RPK bootstrap initialized"
  log_info "server_pub=$server_pub"
}

cmd_check_server_state() {
  log_header "Server state"
  status_file "$SERVER_SK_FILE" "server static key"
  status_file "$SERVER_REGISTRY" "device registry"
  status_file "$SERVER_REGISTRY_BAK" "registry backup"
  status_file "$SERVER_REPLAY_CACHE" "replay cache"
}

cmd_check_client_state() {
  log_header "Client state"
  status_file "$CLIENT_DEVICE_ROOT" "device root"
  status_file "$CLIENT_SERVER_PUB" "pinned server public key"
  status_file "$CLIENT_ROLE_CRED" "role credential"
}

cmd_status() {
  ensure_state_dirs
  cmd_check_server_state
  cmd_check_client_state
  if [[ -x "$CLIENT_BIN" ]] && sudo test -f "$CLIENT_DEVICE_ROOT"; then
    log_header "Derived client identity"
    sudo "$CLIENT_BIN" --print-identity || true
  fi
}

cmd_start_server() {
  [[ $# -ge 1 ]] || die "start-server requires <bind_addr>"
  require_bin "$SERVER_BIN"
  ensure_state_dirs
  sudo test -f "$SERVER_SK_FILE" || die "Server key missing. Run sudo ./zk-arche.sh init-rpk first."
  local bind_addr="$1"
  shift
  exec sudo "$SERVER_BIN" --bind "$bind_addr" "$@"
}

cmd_server_local() {
  [[ $# -ge 1 ]] || die "server-local requires <bind_addr>"
  local bind_addr="$1"
  shift
  cmd_start_server "$bind_addr" --pairing "$@"
}

cmd_setup_device() {
  [[ $# -ge 1 ]] || die "setup-device requires <server_ip:port>"
  require_bin "$CLIENT_BIN"
  ensure_state_dirs
  local server="$1"
  shift
  sudo "$CLIENT_BIN" --server "$server" --setup "$@"
}

cmd_auth_device() {
  [[ $# -eq 1 ]] || die "auth-device requires <server_ip:port>"
  require_bin "$CLIENT_BIN"
  ensure_state_dirs
  sudo "$CLIENT_BIN" --server "$1"
}

cmd_client_local() {
  cmd_setup_device "$@"
}

cmd_full_device_onboard() {
  [[ $# -ge 1 ]] || die "full-device-onboard requires <server_ip:port>"
  local server="$1"
  shift
  cmd_setup_device "$server" "$@"
  cmd_auth_device "$server"
}

cmd_reset_client() {
  sudo rm -rf "$CLIENT_STATE_DIR"
  sudo install -d -m 700 "$CLIENT_STATE_DIR"
  log_ok "Client state reset"
}

cmd_reset_server() {
  sudo rm -rf "$SERVER_STATE_DIR"
  sudo install -d -m 700 "$SERVER_STATE_DIR"
  log_ok "Server state reset"
}

cmd_reset_all() {
  cmd_reset_client
  cmd_reset_server
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 1; }
  local command="$1"
  shift
  case "$command" in
    build) cmd_build "$@" ;;
    init-rpk) cmd_init_rpk "$@" ;;
    pin-server) cmd_pin_server "$@" ;;
    show-pinned-key) cmd_show_pinned_key "$@" ;;
    check-server-state) cmd_check_server_state "$@" ;;
    check-client-state) cmd_check_client_state "$@" ;;
    status) cmd_status "$@" ;;
    start-server) cmd_start_server "$@" ;;
    server-local) cmd_server_local "$@" ;;
    setup-device) cmd_setup_device "$@" ;;
    auth-device) cmd_auth_device "$@" ;;
    client-local) cmd_client_local "$@" ;;
    full-device-onboard) cmd_full_device_onboard "$@" ;;
    reset-client) cmd_reset_client "$@" ;;
    reset-server) cmd_reset_server "$@" ;;
    reset-all) cmd_reset_all "$@" ;;
    help|-h|--help) usage ;;
    *) usage; die "Unknown command: $command" ;;
  esac
}

main "$@"
