#!/usr/bin/env bash
# zk-arche.sh — ZK-ARCHE automation script (C version, mutual cert onboarding)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BIN="${PROJECT_ROOT}/c_server"
CLIENT_BIN="${PROJECT_ROOT}/c_client"
CLIENT_STATE_DIR="/var/lib/iot-auth"
CLIENT_SERVER_PUB="${CLIENT_STATE_DIR}/server_pub.bin"
CLIENT_DEVICE_CERT="${CLIENT_STATE_DIR}/device_cert.pem"
CLIENT_DEVICE_KEY="${CLIENT_STATE_DIR}/device_key.pem"
CLIENT_CA_CERT="${CLIENT_STATE_DIR}/ca_cert.pem"
SERVER_CERT="${PROJECT_ROOT}/server_cert.pem"
SERVER_CERT_KEY="${PROJECT_ROOT}/server_cert_key.pem"
SERVER_CA_CERT="${PROJECT_ROOT}/ca_cert.pem"
SERVER_CA_KEY="${PROJECT_ROOT}/ca_key.pem"
GEN_DEVICE_CERT="${PROJECT_ROOT}/device_cert.pem"
GEN_DEVICE_KEY="${PROJECT_ROOT}/device_key.pem"
SERVER_PUB_HEX_FILE="${PROJECT_ROOT}/server_pub.hex"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  _R='\033[0;31m' _G='\033[0;32m' _Y='\033[0;33m'
  _B='\033[0;34m' _C='\033[0;36m' _W='\033[1;37m' _N='\033[0m'
else
  _R='' _G='' _Y='' _B='' _C='' _W='' _N=''
fi

log_info()   { echo -e "${_B}[INFO]${_N}  $*"; }
log_ok()     { echo -e "${_G}[OK]${_N}    $*"; }
log_warn()   { echo -e "${_Y}[WARN]${_N}  $*"; }
log_error()  { echo -e "${_R}[ERROR]${_N} $*" >&2; }
log_step()   { echo -e "${_C}[STEP]${_N}  $*"; }
log_header() { echo -e "\n${_W}==> $*${_N}"; }
log_val()    { echo -e "    ${_Y}$1${_N}  $2"; }
die() { log_error "$*"; exit 1; }

require_bin() {
  local bin="$1"
  [[ -x "$bin" ]] || die "Binary not found or not executable: $bin
Build first with: ./zk-arche.sh build"
}

require_file() {
  local f="$1"
  [[ -f "$f" ]] || die "Required file not found: $f"
}

validate_hex32() {
  local val="$1" label="$2"
  [[ "$val" =~ ^[0-9a-fA-F]{64}$ ]] || die "$label must be exactly 32 bytes (64 hex characters)"
}

ensure_client_state_dir() {
  sudo mkdir -p "$CLIENT_STATE_DIR"
}

usage() {
  cat <<EOF2

${_W}ZK-ARCHE automation script (C version)${_N}

${_C}USAGE${_N}
  ./zk-arche.sh <command> [options]

${_C}BUILD${_N}
  build

${_C}CERTIFICATE COMMANDS${_N}
  make-certs [--device-id <hex>] [--device-pub <hex>] [--server-pub <hex>]
  install-client-certs
  check-server-certs
  check-client-certs

${_C}SERVER COMMANDS${_N}
  start-server <bind_addr> [opts]
  server-local <bind_addr>
  reset-server

${_C}CLIENT COMMANDS${_N}
  setup-device <server_ip:port> [--pairing-token <token>]
  auth-device <server_ip:port>
  show-pinned-key
  pin-server <server_pub_hex>
  reset-client
  status

${_C}COMBINED FLOWS${_N}
  client-local <server_ip:port> [--pairing-token <token>]
  full-device-onboard <server_ip:port> [--pairing-token <token>]
  reset-all

EOF2
}

cmd_build() {
  log_header "Building C binaries"
  gcc -O2 -std=c11 -Wall -Wextra "${PROJECT_ROOT}/server.c" -o "$SERVER_BIN" -lsodium -lssl -lcrypto
  gcc -O2 -std=c11 -Wall -Wextra "${PROJECT_ROOT}/client.c" -o "$CLIENT_BIN" -lsodium -lssl -lcrypto
  log_ok "Server: $SERVER_BIN"
  log_ok "Client: $CLIENT_BIN"
}

cmd_make_certs() {
  local device_id="$(openssl rand -hex 32)"
  local device_pub="UNBOUND_DEVICE_STATIC_PUB"
  local server_pub="UNBOUND_SERVER_STATIC_PUB"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --device-id)
        [[ $# -ge 2 ]] || die "--device-id requires a value"
        device_id="$2"; validate_hex32 "$device_id" "device_id"; shift 2 ;;
      --device-pub)
        [[ $# -ge 2 ]] || die "--device-pub requires a value"
        device_pub="$2"; shift 2 ;;
      --server-pub)
        [[ $# -ge 2 ]] || die "--server-pub requires a value"
        server_pub="$2"; shift 2 ;;
      *) die "make-certs: unknown option: $1" ;;
    esac
  done

  log_header "Generating CA, server cert, and device cert"

  openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
    -keyout "$SERVER_CA_KEY" -out "$SERVER_CA_CERT" \
    -subj "/CN=ZK-ARCHE Demo CA" >/dev/null 2>&1

  openssl req -new -newkey rsa:3072 -nodes \
    -keyout "$SERVER_CERT_KEY" -out "${PROJECT_ROOT}/server.csr" \
    -subj "/CN=zk-arche-server/OU=${server_pub}" >/dev/null 2>&1
  openssl x509 -req -in "${PROJECT_ROOT}/server.csr" \
    -CA "$SERVER_CA_CERT" -CAkey "$SERVER_CA_KEY" -CAcreateserial \
    -out "$SERVER_CERT" -days 825 -sha256 >/dev/null 2>&1

  openssl req -new -newkey rsa:3072 -nodes \
    -keyout "$GEN_DEVICE_KEY" -out "${PROJECT_ROOT}/device.csr" \
    -subj "/CN=${device_id}/OU=${device_pub}" >/dev/null 2>&1
  openssl x509 -req -in "${PROJECT_ROOT}/device.csr" \
    -CA "$SERVER_CA_CERT" -CAkey "$SERVER_CA_KEY" -CAcreateserial \
    -out "$GEN_DEVICE_CERT" -days 825 -sha256 >/dev/null 2>&1

  log_ok "Generated CA and enrollment certs"
  log_val "CA cert:" "$SERVER_CA_CERT"
  log_val "Server cert:" "$SERVER_CERT"
  log_val "Server key:" "$SERVER_CERT_KEY"
  log_val "Device cert:" "$GEN_DEVICE_CERT"
  log_val "Device key:" "$GEN_DEVICE_KEY"
  log_warn "If your C binaries strictly verify device_pub/server_pub binding, replace placeholder OU values with the exact protocol public keys."
}

cmd_install_client_certs() {
  log_header "Installing client cert material"
  require_file "$GEN_DEVICE_CERT"
  require_file "$GEN_DEVICE_KEY"
  require_file "$SERVER_CA_CERT"
  ensure_client_state_dir
  sudo cp "$GEN_DEVICE_CERT" "$CLIENT_DEVICE_CERT"
  sudo cp "$GEN_DEVICE_KEY" "$CLIENT_DEVICE_KEY"
  sudo cp "$SERVER_CA_CERT" "$CLIENT_CA_CERT"
  sudo chmod 600 "$CLIENT_DEVICE_KEY"
  log_ok "Client cert material installed in $CLIENT_STATE_DIR"
}

cmd_check_server_certs() {
  log_header "Server certificate files"
  _status_file "$SERVER_CA_CERT" "ca cert"
  _status_file "$SERVER_CA_KEY" "ca key"
  _status_file "$SERVER_CERT" "server cert"
  _status_file "$SERVER_CERT_KEY" "server cert key"
}

cmd_check_client_certs() {
  log_header "Client certificate files"
  _status_file "$CLIENT_DEVICE_CERT" "device cert"
  _status_file "$CLIENT_DEVICE_KEY" "device key"
  _status_file "$CLIENT_CA_CERT" "ca cert"
}

cmd_start_server() {
  require_bin "$SERVER_BIN"
  [[ $# -ge 1 ]] || die "start-server requires <bind_addr>"
  local bind_addr="$1"; shift
  require_file "$SERVER_CERT"
  require_file "$SERVER_CERT_KEY"
  require_file "$SERVER_CA_CERT"
  log_header "Starting server"
  log_info "Bind: $bind_addr"
  [[ $# -gt 0 ]] && log_info "Flags: $*"
  exec "$SERVER_BIN" --bind "$bind_addr" "$@"
}

cmd_server_local() {
  require_bin "$SERVER_BIN"
  [[ $# -eq 1 ]] || die "server-local requires <bind_addr>"
  require_file "$SERVER_CERT"
  require_file "$SERVER_CERT_KEY"
  require_file "$SERVER_CA_CERT"
  local bind_addr="$1"
  log_header "Local test mode — server"
  log_info "Bind: $bind_addr"
  log_info "Pairing: enabled"
  echo
  log_info "In a second terminal run:"
  echo -e "    ${_Y}./zk-arche.sh install-client-certs${_N}"
  echo -e "    ${_Y}./zk-arche.sh client-local $bind_addr${_N}"
  echo
  exec "$SERVER_BIN" --bind "$bind_addr" --pairing
}

cmd_pin_server() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "pin-server requires <server_pub_hex>"
  local server_pub="$1"
  validate_hex32 "$server_pub" "server_pub_hex"
  log_step "Pinning server public key..."
  "$CLIENT_BIN" --pin-server-pub "$server_pub"
  printf '%s\n' "$server_pub" > "$SERVER_PUB_HEX_FILE"
  log_ok "Server public key pinned"
}

cmd_setup_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 1 ]] || die "setup-device requires <server_ip:port>"
  require_file "$CLIENT_DEVICE_CERT"
  require_file "$CLIENT_DEVICE_KEY"
  require_file "$CLIENT_CA_CERT"
  local server_addr="$1"; shift
  local extra_flags=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        extra_flags+=(--pairing-token "$2"); shift 2 ;;
      *) die "setup-device: unknown option: $1" ;;
    esac
  done

  log_header "Device setup (mutual certificate onboarding)"
  log_info "Server: $server_addr"
  [[ ${#extra_flags[@]} -gt 0 ]] && log_info "Extra flags: ${extra_flags[*]}"
  "$CLIENT_BIN" --server "$server_addr" --setup "${extra_flags[@]}"
  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local pinned_hex
    pinned_hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_ok "Device enrolled. Operational server key present."
    [[ -n "$pinned_hex" ]] && log_val "Fingerprint:" "$pinned_hex"
  else
    log_ok "Device enrolled"
  fi
}

cmd_auth_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "auth-device requires <server_ip:port>"
  log_header "Device authentication"
  log_info "Server: $1"
  "$CLIENT_BIN" --server "$1"
  log_ok "Authentication complete"
}

cmd_show_pinned_key() {
  if [[ ! -f "$CLIENT_SERVER_PUB" ]]; then
    log_warn "No pinned server key found at: $CLIENT_SERVER_PUB"
    return
  fi
  local hex
  hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB")"
  log_ok "Pinned server public key:"
  log_val "File:" "$CLIENT_SERVER_PUB"
  log_val "Fingerprint:" "$hex"
}

_status_file() {
  local path="$1" label="$2"
  if [[ -f "$path" ]]; then
    local size
    size="$(wc -c < "$path" | tr -d ' ')"
    log_ok "$label: present (${size}B)"
  else
    log_warn "$label: absent"
  fi
}

cmd_status() {
  log_header "ZK-ARCHE status (C version)"
  echo -e "\n${_W}Binaries${_N}"
  [[ -x "$SERVER_BIN" ]] && log_ok "c_server binary: $SERVER_BIN" || log_warn "c_server binary: not built ($SERVER_BIN)"
  [[ -x "$CLIENT_BIN" ]] && log_ok "c_client binary: $CLIENT_BIN" || log_warn "c_client binary: not built ($CLIENT_BIN)"

  echo -e "\n${_W}Server state${_N}  ($PROJECT_ROOT)"
  _status_file "${PROJECT_ROOT}/registry.bin" "device registry"
  _status_file "${PROJECT_ROOT}/server_sk.bin" "server static key"
  _status_file "$SERVER_CA_CERT" "ca cert"
  _status_file "$SERVER_CA_KEY" "ca key"
  _status_file "$SERVER_CERT" "server cert"
  _status_file "$SERVER_CERT_KEY" "server cert key"

  echo -e "\n${_W}Client state${_N}  ($CLIENT_STATE_DIR)"
  _status_file "${CLIENT_STATE_DIR}/device_root.bin" "device root"
  _status_file "$CLIENT_DEVICE_CERT" "device cert"
  _status_file "$CLIENT_DEVICE_KEY" "device key"
  _status_file "$CLIENT_CA_CERT" "ca cert"
  _status_file "$CLIENT_SERVER_PUB" "pinned server pub"
  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local hex
    hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_val "  fingerprint:" "$hex"
  fi
}

cmd_client_local() {
  [[ $# -ge 1 ]] || die "client-local requires <server_ip:port>"
  local server_addr="$1"; shift
  local pairing_token_flags=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        pairing_token_flags+=(--pairing-token "$2"); shift 2 ;;
      *) die "client-local: unknown option: $1" ;;
    esac
  done
  require_file "$CLIENT_DEVICE_CERT"
  require_file "$CLIENT_DEVICE_KEY"
  require_file "$CLIENT_CA_CERT"
  log_header "Local onboarding — client terminal"
  log_info "Server: $server_addr"
  log_step "Running device setup..."
  "$CLIENT_BIN" --server "$server_addr" --setup "${pairing_token_flags[@]}"
  log_ok "Setup complete"
}

cmd_full_device_onboard() {
  [[ $# -ge 1 ]] || die "full-device-onboard requires <server_ip:port>"
  local server_addr="$1"; shift
  local setup_args=("$server_addr")
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        setup_args+=(--pairing-token "$2"); shift 2 ;;
      *) die "full-device-onboard: unknown option: $1" ;;
    esac
  done
  cmd_check_client_certs
  cmd_setup_device "${setup_args[@]}"
}

cmd_reset_client() {
  log_warn "Resetting client state: $CLIENT_STATE_DIR"
  sudo rm -rf "$CLIENT_STATE_DIR"
  log_ok "Client state removed"
}

cmd_reset_server() {
  log_warn "Resetting server state in: $PROJECT_ROOT"
  rm -f "${PROJECT_ROOT}/registry.bin" \
        "${PROJECT_ROOT}/registry.bak" \
        "${PROJECT_ROOT}/server_sk.bin" \
        "${PROJECT_ROOT}/server_pub.bin" \
        "${PROJECT_ROOT}/server_pub.hex" \
        "$SERVER_CERT" "$SERVER_CERT_KEY" \
        "$SERVER_CA_CERT" "$SERVER_CA_KEY" \
        "$GEN_DEVICE_CERT" "$GEN_DEVICE_KEY" \
        "${PROJECT_ROOT}/device.csr" "${PROJECT_ROOT}/server.csr" \
        "${PROJECT_ROOT}/ca_cert.srl"
  log_ok "Server state removed"
}

cmd_reset_all() {
  cmd_reset_server
  cmd_reset_client
  log_ok "All state removed"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi
  local cmd="$1"; shift
  case "$cmd" in
    build) cmd_build "$@" ;;
    make-certs) cmd_make_certs "$@" ;;
    install-client-certs) cmd_install_client_certs "$@" ;;
    check-server-certs) cmd_check_server_certs "$@" ;;
    check-client-certs) cmd_check_client_certs "$@" ;;
    start-server) cmd_start_server "$@" ;;
    server-local) cmd_server_local "$@" ;;
    pin-server) cmd_pin_server "$@" ;;
    setup-device) cmd_setup_device "$@" ;;
    auth-device) cmd_auth_device "$@" ;;
    show-pinned-key) cmd_show_pinned_key "$@" ;;
    status) cmd_status "$@" ;;
    client-local) cmd_client_local "$@" ;;
    full-device-onboard) cmd_full_device_onboard "$@" ;;
    reset-client) cmd_reset_client "$@" ;;
    reset-server) cmd_reset_server "$@" ;;
    reset-all) cmd_reset_all "$@" ;;
    -h|--help|help) usage ;;
    *) log_error "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
