#!/usr/bin/env bash
#
# Transit installer and maintenance tool for Debian-based systems
# (Raspberry Pi OS, Debian, Ubuntu).
#
#   sudo ./setup.sh [command] [options]
#
# Run "./setup.sh --help" for the command list.

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

readonly SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME SCRIPT_DIR
readonly APP_DIR="/opt/transit"
readonly APP_USER="transit"
readonly SERVICE="transit"
readonly TUNNEL_SERVICE="transit-tunnel"
readonly TUNNEL_CONF_DIR="/etc/transit"
readonly TUNNEL_CONF="${TUNNEL_CONF_DIR}/cloudflared.yml"
readonly NODE_MAJOR=22
readonly MIN_FREE_MB=1024
readonly STATE_DIR="/var/lib/transit-setup"
readonly LOCK_FILE="/var/lock/transit-setup.lock"

COMMAND="install"
DATA_DIR=""
INSTALL_CLOUDFLARED="ask"
TUNNEL_NAME=""
TUNNEL_HOST=""
CLOUDFLARED_SRC="/root/.cloudflared"
REBUILD=0
PURGE=0
ASSUME_YES=0
DRY_RUN=0
VERBOSE=0
USE_COLOR=1
LOG_FILE="/var/log/transit-setup.log"
NODE_BIN=""
TMP_DIR=""
DOCTOR_FAILS=0
DOCTOR_WARNS=0
ROLLBACK_ARMED=0
C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

setup_colors() {
  if (( USE_COLOR )) && [[ -t 1 && -z "${NO_COLOR:-}" ]] && command -v tput >/dev/null 2>&1; then
    if [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
      C_RESET="$(tput sgr0)" C_BOLD="$(tput bold)" C_DIM="$(tput dim)"
      C_RED="$(tput setaf 1)" C_GREEN="$(tput setaf 2)" C_YELLOW="$(tput setaf 3)" C_BLUE="$(tput setaf 4)"
    fi
  fi
}

log_file() { { printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG_FILE"; } 2>/dev/null || true; }
info()  { printf '    %s\n' "$*"; log_file "INFO $*"; }
ok()    { printf '%s[ ok ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; log_file "OK   $*"; }
warn()  { printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; log_file "WARN $*"; }
fail()  { printf '%s[fail]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; log_file "FAIL $*"; }
die()   { fail "$*"; exit 1; }
step()  { printf '\n%s%s[%s/%s]%s %s%s%s\n' "$C_BOLD" "$C_BLUE" "$1" "$2" "$C_RESET" "$C_BOLD" "$3" "$C_RESET"; log_file "STEP $1/$2 $3"; }

# Runs a command quietly (output goes to the log). Honours --dry-run and --verbose.
run() {
  local IFS=' ' shown
  shown="$*"
  shown="${shown//$PATH/<PATH>}"
  log_file "+ ${shown}"
  if (( DRY_RUN )); then
    printf '    %s[dry-run]%s %s\n' "$C_DIM" "$C_RESET" "$shown"
    return 0
  fi
  if (( VERBOSE )); then
    "$@" 2>&1 | tee -a "$LOG_FILE"
    return "${PIPESTATUS[0]}"
  fi
  "$@" >>"$LOG_FILE" 2>&1
}

run_as_app() {
  run runuser -u "$APP_USER" -- env HOME="$APP_DIR" PATH="$PATH" "$@"
}

ask_yes() {
  (( ASSUME_YES )) && return 0
  [[ -t 0 ]] || return 1
  local reply
  read -r -p "    $1 [y/N] " reply
  [[ "$reply" =~ ^([yY]|[yY][eE][sS])$ ]]
}

# ---------------------------------------------------------------------------
# Error handling and cleanup
# ---------------------------------------------------------------------------

on_error() {
  local code=$? line="$1"
  trap - ERR
  fail "Command failed at line ${line} (exit code ${code}). Last log lines:"
  if [[ -r "$LOG_FILE" ]]; then tail -n 15 "$LOG_FILE" | sed 's/^/    /' >&2; fi
  fail "Full log: ${LOG_FILE}"
  exit "$code"
}

cleanup() {
  local code=$?
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then rm -rf "$TMP_DIR"; fi
  # A failed update or reinstall restores the version saved by snapshot_code.
  if (( code != 0 && ROLLBACK_ARMED )); then
    ROLLBACK_ARMED=0
    rollback || true
  fi
  return 0
}

trap 'on_error $LINENO' ERR
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
  cat <<EOF
Transit installer ${SCRIPT_VERSION}

Usage: sudo ./${SCRIPT_NAME} [command] [options]

Commands:
  install      Install or reconfigure Transit (default)
  update       Deploy new code and keep configuration and stored files; rolls back on failure
  tunnel       Connect an existing named Cloudflare tunnel (needs --tunnel and --hostname)
  status       Show service, tunnel and health information
  doctor       Run security and health checks (changes nothing)
  uninstall    Remove the services; add --purge to also delete the user, code, config and files

Options:
  --data-dir PATH     Store files in PATH (for example a USB drive) instead of ${APP_DIR}/data
  --tunnel NAME       Name (or UUID) of an existing named tunnel to use instead of a quick tunnel
  --hostname HOST     Public hostname routed to that tunnel, for example files.example.com
  --cloudflared-dir D Directory holding cert.pem and the tunnel credentials (default ${CLOUDFLARED_SRC})
  --no-cloudflared    Do not offer to install cloudflared
  --rebuild           Compile from src/ even when a prebuilt dist/ is present
  --purge             With uninstall: also delete code, configuration and stored files
  -y, --yes           Answer yes to confirmation questions (the password prompt is never skipped)
  -n, --dry-run       Print what would change without changing anything
  -v, --verbose       Show command output instead of only logging it
      --no-color      Disable colours
  -h, --help          Show this help
      --version       Show the script version

Examples:
  sudo ./${SCRIPT_NAME}
  sudo ./${SCRIPT_NAME} install --data-dir /mnt/usb/transit
  sudo ./${SCRIPT_NAME} tunnel --tunnel transit --hostname files.example.com
  sudo ./${SCRIPT_NAME} update
  sudo ./${SCRIPT_NAME} doctor
EOF
}

parse_args() {
  local positional_seen=0
  while (( $# > 0 )); do
    case "$1" in
      install|update|tunnel|status|doctor|uninstall)
        (( positional_seen )) && die "only one command may be given"
        COMMAND="$1"; positional_seen=1; shift ;;
      --data-dir)
        (( $# >= 2 )) || die "--data-dir needs a path"
        DATA_DIR="$2"; shift 2 ;;
      --tunnel)
        (( $# >= 2 )) || die "--tunnel needs a tunnel name"
        TUNNEL_NAME="$2"; shift 2 ;;
      --hostname)
        (( $# >= 2 )) || die "--hostname needs a host name"
        TUNNEL_HOST="${2,,}"; shift 2 ;;
      --cloudflared-dir)
        (( $# >= 2 )) || die "--cloudflared-dir needs a path"
        CLOUDFLARED_SRC="$2"; shift 2 ;;
      --no-cloudflared) INSTALL_CLOUDFLARED="no"; shift ;;
      --rebuild)        REBUILD=1; shift ;;
      --purge)          PURGE=1; shift ;;
      -y|--yes)         ASSUME_YES=1; shift ;;
      -n|--dry-run)     DRY_RUN=1; shift ;;
      -v|--verbose)     VERBOSE=1; shift ;;
      --no-color)       USE_COLOR=0; shift ;;
      --version)        echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"; exit 0 ;;
      -h|--help)        usage; exit 0 ;;
      *)                usage >&2; die "unknown argument: $1" ;;
    esac
  done

  if (( DRY_RUN )); then LOG_FILE="/dev/null"; fi
  if [[ -n "$DATA_DIR" ]]; then
    [[ "$DATA_DIR" == /* ]] || die "--data-dir must be an absolute path"
    [[ "$DATA_DIR" != *[[:space:]]* ]] || die "--data-dir must not contain spaces"
  fi
  if (( PURGE )) && [[ "$COMMAND" != "uninstall" ]]; then die "--purge only applies to the uninstall command"; fi

  if [[ -n "$TUNNEL_NAME" || -n "$TUNNEL_HOST" || "$COMMAND" == "tunnel" ]]; then
    [[ -n "$TUNNEL_NAME" && -n "$TUNNEL_HOST" ]] || die "--tunnel and --hostname must be given together"
    [[ "$TUNNEL_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid tunnel name: ${TUNNEL_NAME}"
    [[ "$TUNNEL_HOST" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]] || die "invalid host name: ${TUNNEL_HOST}"
    [[ "$CLOUDFLARED_SRC" == /* && "$CLOUDFLARED_SRC" != *[[:space:]]* ]] || die "--cloudflared-dir must be an absolute path without spaces"
    # A named tunnel needs cloudflared, so do not ask about it.
    INSTALL_CLOUDFLARED="yes"
  fi
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

# In dry-run mode problems are reported but do not stop the run.
require() {
  if (( DRY_RUN )); then warn "$1 (ignored in dry-run)"; else die "$1"; fi
}

preflight() {
  if [[ "$(id -u)" -ne 0 ]]; then require "run as root: sudo ./${SCRIPT_NAME} ${COMMAND}"; fi
  command -v apt-get >/dev/null 2>&1 || require "only Debian-based systems (apt) are supported"
  command -v systemctl >/dev/null 2>&1 || require "systemd is required"

  if (( ! DRY_RUN )); then
    install -d -m 755 "$(dirname "$LOG_FILE")" "$STATE_DIR"
    : >>"$LOG_FILE"
    chmod 600 "$LOG_FILE"
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "another run of this script is in progress"
  else
    LOG_FILE="/dev/null"
  fi
  log_file "=== ${SCRIPT_NAME} ${SCRIPT_VERSION} ${COMMAND} started by ${SUDO_USER:-$(id -un)} ==="
}

check_environment() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    aarch64|arm64|x86_64) ok "CPU architecture: ${machine}" ;;
    armv7l) warn "32-bit ARM detected, 64-bit Raspberry Pi OS is recommended" ;;
    *) require "unsupported CPU architecture: ${machine}" ;;
  esac

  local free_mb target
  target="/opt"
  [[ -d "$APP_DIR" ]] && target="$APP_DIR"
  free_mb="$(df -Pm "$target" 2>/dev/null | awk 'NR==2 {print $4}' || true)"
  if [[ -n "$free_mb" && "$free_mb" -lt "$MIN_FREE_MB" ]]; then
    require "only ${free_mb} MB free on ${target}, at least ${MIN_FREE_MB} MB are needed"
  else
    ok "Free disk space: ${free_mb:-unknown} MB"
  fi

  local mem_kb
  mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
  mem_kb="${mem_kb:-0}"
  if [[ "${mem_kb:-0}" -gt 0 && "$mem_kb" -lt 700000 ]]; then
    warn "Low memory ($((mem_kb / 1024)) MB). Transit streams data, but add swap if the build fails."
  fi

  check_time_sync
}

check_time_sync() {
  if ! command -v timedatectl >/dev/null 2>&1; then return 0; fi
  if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)" == "yes" ]]; then
    ok "Clock is synchronised (needed for TOTP codes and file expiry)"
  else
    warn "Clock is not synchronised. TOTP codes and file expiry depend on correct time."
  fi
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

installed() { [[ -f "${APP_DIR}/dist/src/main.js" ]]; }

node_major() {
  command -v node >/dev/null 2>&1 || { echo 0; return; }
  node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0
}

# Reads a top-level value from config.json, falling back to a default.
cfg_get() {
  local key="$1" default="${2:-}"
  [[ -f "${APP_DIR}/config.json" ]] || { echo "$default"; return; }
  "${NODE_BIN:-node}" -e '
    try {
      const value = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))[process.argv[2]];
      console.log(value === undefined || value === null ? process.argv[3] : (typeof value === "object" ? JSON.stringify(value) : value));
    } catch { console.log(process.argv[3]); }
  ' "${APP_DIR}/config.json" "$key" "$default" 2>/dev/null || echo "$default"
}

effective_data_dir() {
  local configured
  configured="$(cfg_get dataDir data)"
  if [[ "$configured" == /* ]]; then echo "$configured"; else echo "${APP_DIR}/${configured}"; fi
}

app_version() {
  "${NODE_BIN:-node}" -p "require('${APP_DIR}/package.json').version" 2>/dev/null || echo "unknown"
}

health_check() {
  local port
  port="$(cfg_get port 8787)"
  for _ in $(seq 1 20); do
    if curl -fsS --max-time 2 "http://127.0.0.1:${port}/api/session" 2>/dev/null | grep -q '"authenticated"'; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
# Install steps
# ---------------------------------------------------------------------------

ensure_node() {
  if [[ "$(node_major)" -ge "$NODE_MAJOR" ]]; then
    NODE_BIN="$(command -v node)"
    ok "Node.js $("$NODE_BIN" --version) at ${NODE_BIN}"
    return 0
  fi

  local machine arch base file sha
  machine="$(uname -m)"
  case "$machine" in
    aarch64|arm64) arch="arm64" ;;
    armv7l)        arch="armv7l" ;;
    x86_64)        arch="x64" ;;
    *)             die "unsupported CPU architecture: ${machine}" ;;
  esac

  info "Installing Node.js ${NODE_MAJOR}.x from nodejs.org (SHA-256 verified)"
  run apt-get update -y
  run apt-get install -y --no-install-recommends curl ca-certificates xz-utils

  base="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
  TMP_DIR="$(mktemp -d)"
  if (( DRY_RUN )); then
    info "[dry-run] would download and verify the ${arch} build from ${base}"
    NODE_BIN="/usr/local/bin/node"
    return 0
  fi
  curl -fsSL "${base}/SHASUMS256.txt" -o "${TMP_DIR}/SHASUMS256.txt"
  IFS=' ' read -r sha file < <(grep -E "linux-${arch}\.tar\.xz\$" "${TMP_DIR}/SHASUMS256.txt" | head -n 1) \
    || die "no Node.js build found for linux-${arch}"
  curl -fsSL "${base}/${file}" -o "${TMP_DIR}/${file}"
  (cd "$TMP_DIR" && echo "${sha}  ${file}" | sha256sum -c - >>"$LOG_FILE" 2>&1) || die "Node.js checksum mismatch"
  tar -xJf "${TMP_DIR}/${file}" -C /usr/local --strip-components=1 --no-same-owner --exclude='*.md' --exclude=LICENSE
  hash -r
  NODE_BIN="$(command -v node)"
  [[ "$(node_major)" -ge "$NODE_MAJOR" ]] || die "Node.js ${NODE_MAJOR}+ is required"
  ok "Installed Node.js $("$NODE_BIN" --version)"
}

ensure_user_and_dirs() {
  if id "$APP_USER" >/dev/null 2>&1; then
    ok "User ${APP_USER} exists"
  else
    run useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
    ok "Created system user ${APP_USER}"
  fi
  run install -d -o "$APP_USER" -g "$APP_USER" -m 700 "$APP_DIR"
  # The service sandbox requires the writable directories to exist.
  run install -d -o "$APP_USER" -g "$APP_USER" -m 700 "${APP_DIR}/data"
  if [[ -n "$DATA_DIR" ]]; then
    run install -d -o "$APP_USER" -g "$APP_USER" -m 700 "$DATA_DIR"
    ok "Data directory: ${DATA_DIR}"
  fi
}

snapshot_code() {
  installed || return 0
  run tar -C "$(dirname "$APP_DIR")" --exclude="$(basename "$APP_DIR")/data" \
    -czf "${STATE_DIR}/previous.tar.gz" "$(basename "$APP_DIR")"
  if (( ! DRY_RUN )); then ROLLBACK_ARMED=1; fi
  ok "Saved the current version for rollback"
}

copy_project() {
  tar -C "$SCRIPT_DIR" \
    --exclude=./node_modules --exclude=./data --exclude=./config.json \
    --exclude=./.git --exclude=./.github --exclude=./.claude \
    -cf - . | tar -C "$APP_DIR" -xf - --no-same-owner
  chown -R "${APP_USER}:${APP_USER}" "$APP_DIR"
}

deploy_code() {
  if [[ "$SCRIPT_DIR" != "$APP_DIR" ]]; then
    run copy_project
    ok "Copied the project to ${APP_DIR}"
  fi
}

install_dependencies() {
  local prebuilt=0
  [[ -f "${APP_DIR}/dist/src/main.js" && -f "${APP_DIR}/dist/web/app.js" ]] && prebuilt=1
  if (( DRY_RUN )) && [[ -f "${SCRIPT_DIR}/dist/src/main.js" ]]; then prebuilt=1; fi

  cd "$APP_DIR" 2>/dev/null || cd "$SCRIPT_DIR"
  if (( prebuilt && ! REBUILD )); then
    run_as_app npm ci --omit=dev --no-audit --no-fund
    ok "Installed runtime dependencies (using the prebuilt dist/)"
    return 0
  fi

  run_as_app npm ci --no-audit --no-fund
  if ! run_as_app npm run build; then
    die "the build failed. Build on another machine ('npm ci && npm run build'), copy dist/ over and run this script again."
  fi
  run_as_app npm prune --omit=dev --no-audit --no-fund
  ok "Installed dependencies and built the project"
}

configure_app() {
  local has_config=0
  [[ -f "${APP_DIR}/config.json" ]] && grep -q '"passwordHash"' "${APP_DIR}/config.json" && has_config=1

  if [[ -n "$DATA_DIR" ]]; then
    if [[ -f "${APP_DIR}/config.json" ]]; then
      run_as_app "$NODE_BIN" -e '
        const fs = require("fs");
        const cfg = JSON.parse(fs.readFileSync("config.json", "utf8"));
        cfg.dataDir = process.argv[1];
        fs.writeFileSync("config.json", JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
      ' "$DATA_DIR"
    else
      run runuser -u "$APP_USER" -- bash -c "umask 077; printf '{\n  \"dataDir\": \"%s\"\n}\n' \"\$1\" > '${APP_DIR}/config.json'" _ "$DATA_DIR"
    fi
  fi

  if (( has_config )); then
    if ! ask_yes "A configuration exists. Run the setup again? (changes the password and deletes stored files)"; then
      ok "Keeping the existing configuration"
      return 0
    fi
  fi

  if (( DRY_RUN )); then info "[dry-run] would run the interactive setup"; return 0; fi
  [[ -t 0 ]] || die "the setup needs an interactive terminal. Run: sudo -u ${APP_USER} ${NODE_BIN} ${APP_DIR}/dist/src/setup.js"
  cd "$APP_DIR"
  runuser -u "$APP_USER" -- env HOME="$APP_DIR" PATH="$PATH" "$NODE_BIN" dist/src/setup.js
  ok "Configuration written"
}

install_units() {
  sed "s#^ExecStart=.*#ExecStart=${NODE_BIN} dist/src/main.js#" "${SCRIPT_DIR}/deploy/transit.service" \
    >"/etc/systemd/system/${SERVICE}.service"
  if [[ -f "$TUNNEL_CONF" ]]; then
    # Named tunnel: credentials live in /etc/transit, readable by the service user only.
    sed -e "s#^ExecStart=.*#ExecStart=$(command -v cloudflared) --no-autoupdate --config ${TUNNEL_CONF} tunnel run#" \
      -e 's#^Description=.*#Description=Cloudflare named tunnel for Transit (start on demand)#' \
      "${SCRIPT_DIR}/deploy/transit-tunnel.service" >"/etc/systemd/system/${TUNNEL_SERVICE}.service"
  else
    install -m 644 "${SCRIPT_DIR}/deploy/transit-tunnel.service" "/etc/systemd/system/${TUNNEL_SERVICE}.service"
  fi

  local data_dir="${DATA_DIR:-}"
  if [[ -z "$data_dir" ]]; then
    data_dir="$(effective_data_dir)"
  fi
  if [[ "$data_dir" != "${APP_DIR}/data" ]]; then
    install -d /etc/systemd/system/${SERVICE}.service.d
    printf '[Service]\nReadWritePaths=%s\n' "$data_dir" >"/etc/systemd/system/${SERVICE}.service.d/data.conf"
  else
    rm -f "/etc/systemd/system/${SERVICE}.service.d/data.conf"
  fi
}

rollback() {
  warn "Rolling back to the previous version"
  if [[ ! -f "${STATE_DIR}/previous.tar.gz" ]]; then
    fail "No snapshot available, nothing to roll back to"
    return 1
  fi
  systemctl stop "$SERVICE" || true
  rm -rf "${APP_DIR}/dist" "${APP_DIR}/node_modules"
  tar -xzf "${STATE_DIR}/previous.tar.gz" -C "$(dirname "$APP_DIR")"
  systemctl start "$SERVICE"
  if health_check; then
    ok "Rolled back, the previous version is running"
  else
    fail "Rollback did not restore a healthy service, see: journalctl -u ${SERVICE}"
  fi
}

start_service() {
  run install_units
  run systemctl daemon-reload
  run systemctl enable "$SERVICE"
  run systemctl restart "$SERVICE"
  (( DRY_RUN )) && return 0

  if health_check; then
    ROLLBACK_ARMED=0
    ok "Transit is running and answering on 127.0.0.1:$(cfg_get port 8787)"
    return 0
  fi
  fail "The service did not become healthy"
  journalctl -u "$SERVICE" -n 25 --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
  exit 1   # the EXIT trap rolls back when a previous version was saved
}

ensure_cloudflared() {
  if command -v cloudflared >/dev/null 2>&1; then
    ok "cloudflared is installed ($(cloudflared --version 2>/dev/null | head -n 1))"
    return 0
  fi
  if [[ "$INSTALL_CLOUDFLARED" == "ask" ]]; then
    if ask_yes "Install cloudflared from Cloudflare's signed apt repository (needed for the tunnel)?"; then
      INSTALL_CLOUDFLARED="yes"
    else
      INSTALL_CLOUDFLARED="no"
    fi
  fi
  if [[ "$INSTALL_CLOUDFLARED" != "yes" ]]; then
    info "Skipping cloudflared. Install it later to open the tunnel."
    return 0
  fi
  run apt-get install -y --no-install-recommends curl ca-certificates gnupg
  run install -d -m 0755 /usr/share/keyrings
  run curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  run bash -c "echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list"
  run apt-get update -y
  run apt-get install -y cloudflared
  ok "Installed cloudflared"
}

uuid_re='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

# Prints the UUID of the named tunnel (accepts a UUID or a tunnel name).
resolve_tunnel_id() {
  local name="$1" id
  if [[ "$name" =~ $uuid_re ]]; then echo "$name"; return 0; fi
  [[ -f "${CLOUDFLARED_SRC}/cert.pem" ]] || die "${CLOUDFLARED_SRC}/cert.pem not found. Run 'cloudflared tunnel login' as root first."
  id="$(cloudflared --origincert "${CLOUDFLARED_SRC}/cert.pem" tunnel list --name "$name" --output json 2>>"$LOG_FILE" \
    | "${NODE_BIN:-node}" -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{const l=JSON.parse(d);console.log(l.length?l[0].id:"")}catch{console.log("")}})')" || true
  [[ "$id" =~ $uuid_re ]] || die "tunnel '${name}' not found for this Cloudflare account"
  echo "$id"
}

write_tunnel_config() {
  local id="$1"
  umask 077
  cat >"$TUNNEL_CONF" <<EOF
tunnel: ${id}
credentials-file: ${TUNNEL_CONF_DIR}/${id}.json
ingress:
  - hostname: ${TUNNEL_HOST}
    service: http://127.0.0.1:$(cfg_get port 8787)
  - service: http_status:404
EOF
  chown "root:${APP_USER}" "$TUNNEL_CONF"
  chmod 640 "$TUNNEL_CONF"
}

# Copies the credentials of an existing named tunnel to a place the service user can read,
# writes its ingress config and restricts Transit to the public host name.
configure_tunnel() {
  [[ -n "$TUNNEL_NAME" ]] || return 0
  local id
  if (( DRY_RUN )); then
    id="00000000-0000-0000-0000-000000000000"
  else
    command -v cloudflared >/dev/null 2>&1 || die "cloudflared is not installed"
    id="$(resolve_tunnel_id "$TUNNEL_NAME")"
    [[ -f "${CLOUDFLARED_SRC}/${id}.json" ]] || die "credentials ${CLOUDFLARED_SRC}/${id}.json not found"
  fi

  run install -d -o root -g "$APP_USER" -m 750 "$TUNNEL_CONF_DIR"
  run install -o "$APP_USER" -g "$APP_USER" -m 600 "${CLOUDFLARED_SRC}/${id}.json" "${TUNNEL_CONF_DIR}/${id}.json"
  run write_tunnel_config "$id"
  # Creates the DNS record; it may already exist, which is fine.
  if ! run cloudflared --origincert "${CLOUDFLARED_SRC}/cert.pem" tunnel route dns --overwrite-dns "$id" "$TUNNEL_HOST"; then
    warn "could not create the DNS record for ${TUNNEL_HOST}. Create a CNAME to ${id}.cfargotunnel.com yourself."
  fi
  ok "Named tunnel ${TUNNEL_NAME} (${id}) routes ${TUNNEL_HOST} to Transit"

  if [[ -f "${APP_DIR}/config.json" ]]; then
    run_as_app "${NODE_BIN:-node}" -e '
      const fs = require("fs");
      const cfg = JSON.parse(fs.readFileSync("config.json", "utf8"));
      cfg.allowedHosts = [process.argv[1], "localhost", "127.0.0.1"];
      fs.writeFileSync("config.json", JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
    ' "$TUNNEL_HOST"
    ok "allowedHosts now accepts ${TUNNEL_HOST}"
  fi
}

print_summary() {
  local data_dir tunnel_hint
  data_dir="$(effective_data_dir)"
  if [[ -f "$TUNNEL_CONF" ]]; then
    tunnel_hint="  (your named tunnel: https://$(grep -m1 'hostname:' "$TUNNEL_CONF" | awk '{print $3}'))"
  else
    tunnel_hint="  (quick tunnel: the https://....trycloudflare.com address is in the journal)"
  fi
  cat <<EOF

${C_BOLD}Done.${C_RESET} Transit listens on 127.0.0.1 only. Open the tunnel only while you need it:

  sudo systemctl start ${TUNNEL_SERVICE}
  journalctl -u ${TUNNEL_SERVICE} -n 20
  sudo systemctl stop ${TUNNEL_SERVICE}
${tunnel_hint}

Maintenance:

  sudo ./${SCRIPT_NAME} status
  sudo ./${SCRIPT_NAME} doctor
  sudo ./${SCRIPT_NAME} update               # after copying new project files next to this script
  tail -f ${data_dir}/audit.log

Log of this run: ${LOG_FILE}
EOF
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_install() {
  local total=6
  step 1 "$total" "Checking the system"
  preflight
  check_environment

  step 2 "$total" "Node.js"
  ensure_node

  step 3 "$total" "User, directories and code"
  ensure_user_and_dirs
  snapshot_code
  deploy_code

  step 4 "$total" "Dependencies and build"
  install_dependencies

  step 5 "$total" "Configuration"
  configure_app

  step 6 "$total" "Service and tunnel"
  ensure_cloudflared
  configure_tunnel
  start_service
  (( DRY_RUN )) || print_summary
}

cmd_tunnel() {
  local total=3
  step 1 "$total" "Checking the system"
  preflight
  installed || die "Transit is not installed. Run: sudo ./${SCRIPT_NAME} install"
  NODE_BIN="$(command -v node)"

  step 2 "$total" "Connecting the named tunnel"
  ensure_cloudflared
  configure_tunnel

  step 3 "$total" "Restarting"
  start_service
  (( DRY_RUN )) || print_summary
}

cmd_update() {
  local total=5
  step 1 "$total" "Checking the system"
  preflight
  installed || die "Transit is not installed. Run: sudo ./${SCRIPT_NAME} install"
  check_environment
  NODE_BIN="$(command -v node)"
  info "Installed version: $(app_version)"

  step 2 "$total" "Saving the current version"
  snapshot_code

  step 3 "$total" "Deploying the new code"
  deploy_code

  step 4 "$total" "Dependencies and build"
  install_dependencies

  step 5 "$total" "Restarting"
  start_service
  ok "Updated to version $(app_version)"
}

cmd_status() {
  preflight
  NODE_BIN="$(command -v node || true)"
  installed || die "Transit is not installed"
  local port
  port="$(cfg_get port 8787)"
  printf '%sTransit%s version %s\n' "$C_BOLD" "$C_RESET" "$(app_version)"
  printf '  service      : %s\n' "$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
  printf '  tunnel       : %s\n' "$(systemctl is-active "$TUNNEL_SERVICE" 2>/dev/null || true)"
  if curl -fsS --max-time 2 "http://127.0.0.1:${port}/api/session" >/dev/null 2>&1; then
    printf '  health       : answering on 127.0.0.1:%s\n' "$port"
  else
    printf '  health       : not answering on 127.0.0.1:%s\n' "$port"
  fi
  printf '  node         : %s\n' "$("${NODE_BIN:-node}" --version 2>/dev/null || echo missing)"
  printf '  data dir     : %s (%s)\n' "$(effective_data_dir)" "$(du -sh "$(effective_data_dir)" 2>/dev/null | cut -f1 || echo '?')"
  printf '  totp         : %s\n' "$([[ "$(cfg_get totpSecret null)" != "null" ]] && echo enabled || echo disabled)"
  printf '  clock synced : %s\n' "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
  if [[ -f "$TUNNEL_CONF" ]]; then
    printf '  tunnel mode  : named (%s)\n' "$(grep -m1 'hostname:' "$TUNNEL_CONF" | awk '{print $3}')"
  else
    printf '  tunnel mode  : quick\n'
  fi
  if [[ ! -f "$TUNNEL_CONF" ]] && systemctl is-active --quiet "$TUNNEL_SERVICE" 2>/dev/null; then
    printf '  tunnel URL   : %s\n' "$(journalctl -u "$TUNNEL_SERVICE" -n 100 --no-pager 2>/dev/null | grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -n 1 || true)"
  fi
}

doctor_check() {
  # doctor_check <pass|warn|fail> <message>
  case "$1" in
    pass) printf '%s[pass]%s %s\n' "$C_GREEN" "$C_RESET" "$2" ;;
    warn) printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$2"; DOCTOR_WARNS=$((DOCTOR_WARNS + 1)) ;;
    fail) printf '%s[fail]%s %s\n' "$C_RED" "$C_RESET" "$2"; DOCTOR_FAILS=$((DOCTOR_FAILS + 1)) ;;
  esac
}

# doctor_test <level if the test fails> <pass message> <fail message> <command...>
doctor_test() {
  local level="$1" pass_msg="$2" fail_msg="$3"
  shift 3
  if "$@"; then doctor_check pass "$pass_msg"; else doctor_check "$level" "$fail_msg"; fi
}

totp_enabled() { [[ "$(cfg_get totpSecret null)" != "null" ]]; }
hosts_restricted() { [[ "$(cfg_get allowedHosts '[]')" != "[]" ]]; }
client_encryption_required() { [[ "$(cfg_get requireClientEncryption true)" == "true" ]]; }
node_is_recent() { [[ "$(node_major)" -ge "$NODE_MAJOR" ]]; }
clock_synced() { [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)" == "yes" ]]; }
tunnel_closed() { ! systemctl is-active --quiet "$TUNNEL_SERVICE" 2>/dev/null; }

cmd_doctor() {
  preflight
  NODE_BIN="$(command -v node || true)"
  installed || die "Transit is not installed"
  local port data_dir mode owner listen

  doctor_test fail "Service is running" "Service is not running" systemctl is-active --quiet "$SERVICE"

  port="$(cfg_get port 8787)"
  listen="$(ss -ltnH "sport = :${port}" 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
  if [[ -z "$listen" ]]; then
    doctor_check fail "Nothing is listening on port ${port}"
  elif [[ "$listen" =~ ^(127\.0\.0\.1|\[::1\]):${port}\ *$ ]]; then
    doctor_check pass "Listening on loopback only (${listen% })"
  else
    doctor_check fail "Listening on a non-loopback address: ${listen}"
  fi

  IFS=' ' read -r mode owner < <(stat -c '%a %U' "${APP_DIR}/config.json" 2>/dev/null || echo "missing missing")
  if [[ "$mode" == "600" && "$owner" == "$APP_USER" ]]; then
    doctor_check pass "config.json is mode 600 and owned by ${APP_USER}"
  else
    doctor_check fail "config.json is mode ${mode}, owner ${owner} (expected 600, ${APP_USER})"
  fi

  data_dir="$(effective_data_dir)"
  IFS=' ' read -r mode owner < <(stat -c '%a %U' "$data_dir" 2>/dev/null || echo "missing missing")
  if [[ "$mode" == "700" && "$owner" == "$APP_USER" ]]; then
    doctor_check pass "Data directory is mode 700 and owned by ${APP_USER}"
  else
    doctor_check fail "Data directory ${data_dir} is mode ${mode}, owner ${owner} (expected 700, ${APP_USER})"
  fi

  doctor_test warn "TOTP second factor is enabled" "TOTP is disabled, the password is the only secret" totp_enabled
  doctor_test warn "allowedHosts is set" "allowedHosts is empty, any Host header is accepted" hosts_restricted
  doctor_test warn "Client-side encryption is required" "Client-side encryption is not required" client_encryption_required
  doctor_test fail "Node.js $("${NODE_BIN:-node}" --version 2>/dev/null)" "Node.js ${NODE_MAJOR}+ is required" node_is_recent
  doctor_test warn "Clock is synchronised" "Clock is not synchronised (TOTP and expiry need correct time)" clock_synced
  doctor_test warn "The tunnel is closed" "The tunnel is open right now (stop it when you are done)" tunnel_closed

  if command -v systemd-analyze >/dev/null 2>&1; then
    info "systemd exposure: $(systemd-analyze security "$SERVICE" --no-pager 2>/dev/null | tail -n 1 | sed 's/^[^A-Za-z]*//')"
  fi

  printf '\n%s failure(s), %s warning(s)\n' "$DOCTOR_FAILS" "$DOCTOR_WARNS"
  [[ "$DOCTOR_FAILS" -eq 0 ]] || exit 1
}

cmd_uninstall() {
  preflight
  NODE_BIN="$(command -v node || true)"
  local data_dir
  data_dir="$(effective_data_dir)"

  if (( PURGE )); then
    warn "--purge deletes ${APP_DIR}, ${data_dir}, the ${APP_USER} user and the setup state. Stored files cannot be recovered."
  fi
  ask_yes "Remove the Transit services?" || die "aborted"
  if (( PURGE )) && (( ! ASSUME_YES )); then
    local reply
    read -r -p "    Type 'delete' to confirm the purge: " reply
    [[ "$reply" == "delete" ]] || die "aborted"
  fi

  run systemctl disable --now "$TUNNEL_SERVICE" || true
  run systemctl disable --now "$SERVICE" || true
  run rm -f "/etc/systemd/system/${SERVICE}.service" "/etc/systemd/system/${TUNNEL_SERVICE}.service"
  run rm -rf "/etc/systemd/system/${SERVICE}.service.d"
  run systemctl daemon-reload
  ok "Services removed"

  if (( PURGE )); then
    run rm -rf "$APP_DIR" "$data_dir" "$STATE_DIR" "$TUNNEL_CONF_DIR"
    if id "$APP_USER" >/dev/null 2>&1; then run userdel "$APP_USER"; fi
    ok "Code, configuration, stored files and user deleted"
  else
    info "Kept ${APP_DIR} and ${data_dir}. Use --purge to delete them."
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  parse_args "$@"
  setup_colors
  case "$COMMAND" in
    install)   cmd_install ;;
    update)    cmd_update ;;
    tunnel)    cmd_tunnel ;;
    status)    cmd_status ;;
    doctor)    cmd_doctor ;;
    uninstall) cmd_uninstall ;;
  esac
}

main "$@"
