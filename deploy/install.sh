#!/usr/bin/env bash
# OpsGate Agent installer.
#
#   curl -fsSL __OPSGATE_CLOUD_URL__/install.sh | sudo bash -s -- --key og_YOUR_KEY
#
# Options
#   --key KEY            license key from your OpsGate dashboard (required for a first install)
#   --domain NAME        public hostname for the agent (DNS must point to this server). Without it,
#                        a free automatic hostname is used: <your-ip>.sslip.io
#   --email ADDRESS      contact for Let's Encrypt (nginx mode only; optional)
#   --proxy MODE         auto (default) | easypanel | caddy | nginx | none
#   --port N             local port for the agent (default 8765, or the next free one)
#   --allow-write DIRS   comma-separated folders the AI may modify (default: none, read-only)
#   --allow-restart SVCS comma-separated systemd services the AI may restart (default: none)
#   --access PROFILES    what the AI may do: readonly (default), network, asterisk, full; comma separated.
#                        Without it, a menu asks (when a terminal is available). Change later: sudo opsgate access
#   --no-firewall        do not open ports 80/443 in ufw/firewalld
#   --fingerprint HEX    refuse unless the vendor release key has this fingerprint (compare with the vendor's website)
#   --update             update an existing installation (keeps password, key and settings)
#
# What it does: creates the unprivileged user "opsgate", installs the agent in /opt/opsgate as a
# hardened systemd service, sets up HTTPS (EasyPanel/Traefik, Caddy or nginx), creates the login
# password ON THIS SERVER (only its hash is stored) and checks everything end to end.
# Nothing it creates leaves this server except anonymous usage counts (see /docs/security).
set -euo pipefail
# The whole script is one brace group: bash reads it completely before running anything, so a
# download cut off halfway (curl | bash) runs nothing instead of half an installer.
{
CLOUD_URL="__OPSGATE_CLOUD_URL__"
AGENT_VERSION="__OPSGATE_VERSION__"
AGENT_SHA256="__OPSGATE_SHA256__"
# Public half of the release-signing key (base64 PEM). The private half never leaves the vendor's
# own computer; it is not on the OpsGate Cloud server.
AGENT_PUBKEY_B64="__OPSGATE_PUBKEY_B64__"
PINNED_KEY=/etc/opsgate/release.pub.pem

KEY=""; DOMAIN=""; EMAIL=""; PROXY="auto"; PORT=""; WRITE_DIRS=""; RESTART_SVCS=""; ACCESS=""
NO_FIREWALL=0; UPDATE=0; TARBALL=""; SIG=""; ALLOW_DOWNGRADE=0; WANT_FPR=""
OPT=/opt/opsgate; APP=$OPT/app; VENV=$OPT/venv; ETC=/etc/opsgate; ENVF=$ETC/env; CONF=$ETC/install.conf
SVC_USER=opsgate; UNIT=opsgate; EASYPANEL_DIR=/etc/easypanel/traefik/config

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; D=$'\e[2m'; N=$'\e[0m'
else B=; G=; Y=; R=; C=; D=; N=; fi
step() { echo; echo "${B}${C}==>${N}${B} $*${N}"; }
ok()   { echo "  ${G}✓${N} $*"; }
info() { echo "  $*"; }
warn() { echo "  ${Y}!${N} $*"; }
die()  { echo; echo "${R}✗ $*${N}" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:-}"; shift 2 ;;          --key=*) KEY="${1#*=}"; shift ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;    --domain=*) DOMAIN="${1#*=}"; shift ;;
    --email) EMAIL="${2:-}"; shift 2 ;;      --email=*) EMAIL="${1#*=}"; shift ;;
    --proxy) PROXY="${2:-}"; shift 2 ;;      --proxy=*) PROXY="${1#*=}"; shift ;;
    --port) PORT="${2:-}"; shift 2 ;;        --port=*) PORT="${1#*=}"; shift ;;
    --allow-write) WRITE_DIRS="${2:-}"; shift 2 ;;     --allow-write=*) WRITE_DIRS="${1#*=}"; shift ;;
    --allow-restart) RESTART_SVCS="${2:-}"; shift 2 ;; --allow-restart=*) RESTART_SVCS="${1#*=}"; shift ;;
    --access) ACCESS="${2:-}"; shift 2 ;;    --access=*) ACCESS="${1#*=}"; shift ;;
    --no-firewall) NO_FIREWALL=1; shift ;;
    --update) UPDATE=1; shift ;;
    --tarball) TARBALL="${2:-}"; shift 2 ;;  # offline/testing: local agent package (needs --sig)
    --sig) SIG="${2:-}"; shift 2 ;;          # signature file of that package
    --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
    --fingerprint) WANT_FPR="${2:-}"; shift 2 ;;  # expected release-key fingerprint (from the vendor's independent channel)
    --cloud) CLOUD_URL="${2:-}"; shift 2 ;;  # testing against another OpsGate Cloud
    -h|--help) sed -n '2,24p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
done
CLOUD_URL="${CLOUD_URL%/}"
case "$CLOUD_URL" in https://*|http://127.0.0.1*|http://localhost*|__*) ;; *) die "The cloud address must use https://" ;; esac

echo "${B}OpsGate Agent installer${N} ${D}${AGENT_VERSION}${N}"

# ------------------------------------------------------------------ preflight
step "Checking this server"
[ "$(id -u)" -eq 0 ] || die "Run as root: curl -fsSL $CLOUD_URL/install.sh | sudo bash -s -- --key ..."
[ "$(uname -s)" = Linux ] || die "OpsGate needs Linux."
[ -d /run/systemd/system ] || die "OpsGate needs systemd (not found)."
case "$CLOUD_URL" in __*) die "This copy of the installer has no cloud address. Download it from your OpsGate dashboard." ;; esac
. /etc/os-release 2>/dev/null || true
ok "${PRETTY_NAME:-Linux} ($(uname -m))"
PKG=""
if have apt-get; then PKG=apt; elif have dnf; then PKG=dnf; elif have yum; then PKG=yum; fi

if [ -f "$PINNED_KEY" ] && [ -z "$TARBALL" ]; then
  die "OpsGate is already installed here. Update or change settings with: sudo opsgate update [--domain NAME]  (it verifies the vendor signature first; re-running a downloaded script would not)."
fi
if [ -f "$CONF" ]; then
  _c() { sed -n "s/^$1=//p" "$CONF" | tail -n1; }
  [ -n "$DOMAIN" ] || DOMAIN="$(_c DOMAIN)"
  [ "$PROXY" != auto ] || PROXY="$(_c PROXY_MODE)"; PROXY="${PROXY:-auto}"
  [ -n "$PORT" ] || PORT="$(_c PORT)"
fi
if [ -z "$KEY" ] && [ -f "$ENVF" ]; then KEY="$(sed -n 's/^OPSGATE_LICENSE_KEY=//p' "$ENVF" | tail -n1)"; fi
if [ "$UPDATE" = 1 ] && [ ! -f "$ENVF" ]; then die "No existing installation to update. Run without --update."; fi
[ -n "$KEY" ] || die "Missing --key. Copy the full command from your dashboard: $CLOUD_URL/dashboard/servers"
[[ "$KEY" =~ ^og_[A-Za-z0-9_-]{30,}$ ]] || die "That license key does not look right (it starts with og_)."
case "$PROXY" in auto|easypanel|caddy|nginx|none) ;; *) die "--proxy must be auto, easypanel, caddy, nginx or none" ;; esac
if [ -n "$DOMAIN" ]; then
  [[ "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || die "Invalid --domain: $DOMAIN"
fi
[ -z "$PORT" ] || [[ "$PORT" =~ ^[0-9]{2,5}$ ]] || die "Invalid --port"

pkg_install() {
  [ $# -gt 0 ] || return 0
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
         DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null ;;
    dnf|yum) "$PKG" install -y -q "$@" >/dev/null ;;
    *) die "Please install: $* (no supported package manager found)" ;;
  esac
}

missing=()
have curl || missing+=(curl)
have setfacl || missing+=(acl)
have sudo || missing+=(sudo)
have visudo || missing+=(sudo)
have ss || missing+=(iproute2)
have tar || missing+=(tar)
have openssl || missing+=(openssl)
have python3 || missing+=(python3)
[ ${#missing[@]} -eq 0 ] || { info "Installing: ${missing[*]}"; pkg_install "${missing[@]}"; }
find_python() {  # newest Python >= 3.10 on this server
  local c
  for c in python3.13 python3.12 python3.11 python3.10 python3; do
    have "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null && { echo "$c"; return 0; }
  done
  return 1
}
PYBIN="$(find_python || true)"
if [ -z "$PYBIN" ] && { [ "$PKG" = dnf ] || [ "$PKG" = yum ]; }; then
  info "Installing Python 3.11 (the system Python is too old)"; pkg_install python3.11 || true; PYBIN="$(find_python || true)"
fi
[ -n "$PYBIN" ] || die "OpsGate needs Python 3.10 or newer (found $(python3 -V 2>&1)). Ubuntu 22.04+ and Debian 12+ include it."
PYV="$("$PYBIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if ! "$PYBIN" -c 'import ensurepip, venv' 2>/dev/null; then
  info "Installing the Python venv module"
  if [ "$PKG" = apt ]; then pkg_install "python${PYV}-venv" 2>/dev/null || pkg_install python3-venv
  else pkg_install python3-pip || true; fi
fi
ok "Python $PYV, systemd, sudo, acl"

# ------------------------------------------------------------------ license
step "Checking your license key"
LIC_FILE="$(mktemp)"; trap 'rm -f "$LIC_FILE"' EXIT
code="$(curl -sS -o "$LIC_FILE" -w '%{http_code}' -H "Authorization: Bearer $KEY" "$CLOUD_URL/api/v1/license" || true)"
case "$code" in
  200) ;;
  401) die "OpsGate Cloud does not recognize this key (revoked or mistyped). Create a new one in $CLOUD_URL/dashboard/servers" ;;
  000) die "Cannot reach $CLOUD_URL from this server. Check its internet access (outbound HTTPS)." ;;
  *) die "OpsGate Cloud answered HTTP $code. Try again in a minute." ;;
esac
LIC_SUMMARY="$("$PYBIN" -c 'import json,sys; d=json.load(open(sys.argv[1])); print("%s · %s plan · account %s" % (d.get("server_name","server"), str(d.get("plan","free")).capitalize(), d.get("account","")))' "$LIC_FILE" 2>/dev/null || echo "key accepted")"
ok "$LIC_SUMMARY"

# ------------------------------------------------------------------ package
step "Downloading and verifying the OpsGate Agent"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" "$LIC_FILE"' EXIT
if [ -n "$TARBALL" ]; then
  [ -f "$TARBALL" ] && [ -f "$SIG" ] || die "--tarball needs a package file and its --sig signature file."
  cp "$TARBALL" "$WORK/agent.tgz"; cp "$SIG" "$WORK/agent.sig"
else
  curl -fsSL "$CLOUD_URL/download/opsgate-agent.tar.gz" -o "$WORK/agent.tgz" || die "Download failed."
  curl -fsSL "$CLOUD_URL/download/opsgate-agent.tar.gz.sig" -o "$WORK/agent.sig" || die "Could not download the package signature."
fi
# Trust anchor: on updates, the key pinned on this server at the first install (a hacked cloud
# server cannot swap it). On the first install, the key embedded in this installer.
if [ -f "$PINNED_KEY" ]; then
  cp "$PINNED_KEY" "$WORK/release.pub.pem"; KEYSRC="pinned on this server"
else
  case "$AGENT_PUBKEY_B64" in ""|__*) die "This installer has no release key. Download it again from your OpsGate dashboard." ;; esac
  printf '%s' "$AGENT_PUBKEY_B64" | base64 -d > "$WORK/release.pub.pem" 2>/dev/null || die "The release key in this installer is damaged."
  KEYSRC="from the installer"
fi
openssl pkey -pubin -in "$WORK/release.pub.pem" -noout 2>/dev/null || die "The release key is not valid."
FPR="$(openssl pkey -pubin -in "$WORK/release.pub.pem" -outform DER 2>/dev/null | sha256sum | cut -c1-16)"
if [ -n "$WANT_FPR" ] && [ "$WANT_FPR" != "$FPR" ]; then
  die "RELEASE KEY MISMATCH: this installer carries key $FPR but you expected $WANT_FPR. Nothing was installed. Do not continue."
fi
if ! openssl dgst -sha256 -verify "$WORK/release.pub.pem" -signature "$WORK/agent.sig" "$WORK/agent.tgz" >/dev/null 2>&1; then
  die "SIGNATURE INVALID: this package was not signed by the OpsGate vendor, or it was altered. Nothing was installed. Do not use it; contact support."
fi
GOT="$(sha256sum "$WORK/agent.tgz" | cut -d' ' -f1)"
case "$AGENT_SHA256" in
  __*) ;;
  *) [ "$GOT" = "$AGENT_SHA256" ] || die "Checksum mismatch: the download is corrupted. Nothing was installed." ;;
esac
tar -xzf "$WORK/agent.tgz" -C "$WORK" --no-same-owner
[ -f "$WORK/opsgate-agent/server.py" ] || die "The package is incomplete."
AGENT_VERSION="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$WORK/opsgate-agent/config.py" | head -n1)"
[[ "$AGENT_VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || die "The package has no valid version."
# Replay protection: an old (but genuinely signed) vulnerable version is refused.
if [ -f "$CONF" ]; then
  CURRENT="$(sed -n 's/^VERSION=//p' "$CONF" | tail -n1)"
  if [ -n "$CURRENT" ] && [ "$ALLOW_DOWNGRADE" != 1 ] && [ "$(printf '%s\n%s\n' "$CURRENT" "$AGENT_VERSION" | sort -V | head -n1)" != "$CURRENT" ]; then
    die "Refusing to go back from version $CURRENT to $AGENT_VERSION (use --allow-downgrade if you really mean it)."
  fi
fi
echo "$AGENT_VERSION" > "$WORK/opsgate-agent/VERSION"
ok "Signature valid · version $AGENT_VERSION · release key $FPR ($KEYSRC)"

# ------------------------------------------------------------------ user and folders
step "Service user and folders"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
fi
for g in adm systemd-journal asterisk; do getent group "$g" >/dev/null && usermod -aG "$g" "$SVC_USER"; done
install -d -o root -g root -m 755 "$OPT"
install -d -o root -g root -m 700 "$ETC"
install -m 644 -o root -g root "$WORK/release.pub.pem" "$PINNED_KEY"   # pin the vendor key: updates are verified against THIS copy
install -d -o "$SVC_USER" -g "$SVC_USER" -m 700 /var/lib/opsgate
install -d -o "$SVC_USER" -g "$SVC_USER" -m 750 /var/log/opsgate /var/backups/opsgate
ok "user $SVC_USER ($(id -nG "$SVC_USER" | tr ' ' ',')) — never root"

step "Installing the agent in $OPT"
rm -rf "$APP.new" "$APP.old"
mv "$WORK/opsgate-agent" "$APP.new"
chown -R root:root "$APP.new"; chmod -R u=rwX,go=rX "$APP.new"
chmod 755 "$APP.new/bin/opsgate" "$APP.new/deploy/"*.sh
[ -d "$APP" ] && mv "$APP" "$APP.old"
mv "$APP.new" "$APP"
rollback() {
  [ -d "$APP.old" ] || { rm -rf "$VENV.old"; return 0; }     # first install: nothing to go back to
  warn "Restoring the previous version"
  rm -rf "$APP"; mv "$APP.old" "$APP"
  if [ -d "$VENV.old" ]; then rm -rf "$VENV"; mv "$VENV.old" "$VENV"; fi
  install -m 755 -o root -g root "$APP/bin/opsgate" /usr/local/bin/opsgate
  if [ -f "$APP/deploy/opsgate-asterisk" ] && have asterisk; then install -m 755 -o root -g root "$APP/deploy/opsgate-asterisk" /usr/local/sbin/opsgate-asterisk; fi
  sed "s#__DOCS_URL__#$CLOUD_URL/docs#" "$APP/deploy/opsgate.service" > /etc/systemd/system/opsgate.service
  systemctl daemon-reload
}
# Keep the current Python environment too: new dependencies must not break the old code if we go back.
rm -rf "$VENV.old"
if [ -d "$APP.old" ] && [ -x "$VENV/bin/python" ]; then cp -a "$VENV" "$VENV.old"; fi
if [ ! -x "$VENV/bin/python" ] || ! "$VENV/bin/python" -c 'import sys; sys.exit(0)' 2>/dev/null; then
  rm -rf "$VENV"; "$PYBIN" -m venv "$VENV" || { rollback; die "Could not create the Python environment."; }
fi
if ! "$VENV/bin/pip" install -q --disable-pip-version-check --no-cache-dir -r "$APP/requirements.txt" >"$WORK/pip.log" 2>&1; then
  tail -n 15 "$WORK/pip.log"; rollback; die "Installing dependencies failed (see above)."
fi
"$VENV/bin/python" -c "import mcp, yaml" || { rollback; die "Dependencies are broken."; }
install -m 755 -o root -g root "$APP/bin/opsgate" /usr/local/bin/opsgate
if have asterisk; then install -m 755 -o root -g root "$APP/deploy/opsgate-asterisk" /usr/local/sbin/opsgate-asterisk; fi
ok "OpsGate Agent $AGENT_VERSION installed, management command: opsgate"

# ------------------------------------------------------------------ network plan
step "Network and HTTPS"
port_busy() { ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q .; }
ours_on() { systemctl is-active -q "$UNIT" 2>/dev/null && [ "$(sed -n 's/^MCP_PORT=//p' "$ENVF" 2>/dev/null)" = "$1" ]; }
gw_ip() { ip -4 addr show 2>/dev/null | grep -q '172.18.0.1/'; }
if [ "$PROXY" = auto ]; then
  if [ -d "$EASYPANEL_DIR" ] && gw_ip; then PROXY=easypanel
  elif have caddy && systemctl is-active -q caddy 2>/dev/null; then PROXY=caddy
  elif port_busy 443 || port_busy 80; then
    if have nginx && systemctl is-active -q nginx 2>/dev/null; then PROXY=nginx; else PROXY=none; fi
  else PROXY=caddy; fi
fi
BIND=127.0.0.1
[ "$PROXY" = easypanel ] && { gw_ip || die "EasyPanel found but 172.18.0.1 (docker_gwbridge) is missing. Is Docker running?"; BIND=172.18.0.1; }
if [ -z "$PORT" ]; then
  PORT=8765
  while port_busy "$PORT" && ! ours_on "$PORT"; do PORT=$((PORT + 1)); [ "$PORT" -le 8799 ] || die "No free port between 8765 and 8799."; done
elif port_busy "$PORT" && ! ours_on "$PORT"; then die "Port $PORT is already used by another program (use --port)."; fi
if [ -z "$DOMAIN" ]; then
  IP="$(curl -fsS "$CLOUD_URL/api/v1/ip" 2>/dev/null | tr -d '[:space:]' || true)"
  [[ "$IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "Could not detect this server's public IPv4 address. Use --domain."
  DOMAIN="${IP//./-}.sslip.io"
  info "No --domain given: using the free automatic hostname $DOMAIN"
fi
RESOLVED="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}' || true)"
MYIP="${IP:-$(curl -fsS "$CLOUD_URL/api/v1/ip" 2>/dev/null | tr -d '[:space:]' || true)}"
if [ -z "$RESOLVED" ]; then warn "$DOMAIN does not resolve yet. Point its DNS (A record) to ${MYIP:-this server}."
elif [ -n "$MYIP" ] && [ "$RESOLVED" != "$MYIP" ]; then warn "$DOMAIN points to $RESOLVED but this server is $MYIP. HTTPS will fail until DNS is fixed."
else ok "$DOMAIN → $RESOLVED"; fi
ok "proxy: $PROXY · agent listens on $BIND:$PORT (not exposed directly)"

# ------------------------------------------------------------------ configuration
step "Configuration ($ENVF, readable by root only)"
E() { "$VENV/bin/python" "$APP/scripts/envfile.py" "$ENVF" "$@"; }
FIRST=0; [ -f "$ENVF" ] || FIRST=1
E set "MCP_HOST=$BIND" "MCP_PORT=$PORT" "MCP_PUBLIC_URL=https://$DOMAIN" \
      "MCP_ALLOWED_HOSTS=$DOMAIN,$BIND:$PORT,127.0.0.1:$PORT,localhost:$PORT" \
      "MCP_STATE_DIR=/var/lib/opsgate" "MCP_AUDIT_FILE=/var/log/opsgate/audit.jsonl" "MCP_BACKUP_DIR=/var/backups/opsgate" \
      "OPSGATE_LICENSE_KEY=$KEY" "OPSGATE_CLOUD_URL=$CLOUD_URL"
chmod 600 "$ENVF"
PASSWORD=""
if ! grep -q '^MCP_ADMIN_PASSWORD_HASH=.\+' "$ENVF"; then
  PASSWORD="$("$VENV/bin/python" "$APP/scripts/set_password.py" --env "$ENVF" --random)"
  ok "Login password created (only its scrypt hash is stored)"
else
  ok "Existing login password kept (change it with: sudo opsgate password)"
fi
grep -q '^MCP_TOKEN_SHA256=' "$ENVF" || E set "MCP_TOKEN_SHA256="
touch "$ETC/write-paths" "$ETC/read-paths" "$ETC/restart-services"; chmod 600 "$ETC/write-paths" "$ETC/read-paths" "$ETC/restart-services"
{
  echo "CLOUD_URL=$CLOUD_URL"; echo "DOMAIN=$DOMAIN"; echo "PROXY_MODE=$PROXY"; echo "BIND=$BIND"; echo "PORT=$PORT"
  echo "VERSION=$AGENT_VERSION"; echo "UPDATED=$(date -u +%FT%TZ)"
} > "$CONF"; chmod 600 "$CONF"

# ------------------------------------------------------------------ permissions
step "Permissions (read-only unless you allow more)"
IFS=',' read -ra _w <<< "$WRITE_DIRS"
for d in "${_w[@]}"; do [ -n "$d" ] && { /usr/local/bin/opsgate allow-write "$d" >/dev/null && ok "may write in $d" || warn "skipped $d"; }; done
IFS=',' read -ra _s <<< "$RESTART_SVCS"
for s in "${_s[@]}"; do [ -n "$s" ] && { /usr/local/bin/opsgate allow-restart "$s" >/dev/null && ok "may restart $s" || warn "skipped $s"; }; done
/usr/local/bin/opsgate _apply
if [ "${UPDATE:-0}" != "1" ]; then
  if [ -n "${ACCESS:-}" ]; then
    _ap=(); IFS=',' read -ra _p <<< "$ACCESS"; for x in "${_p[@]}"; do [ -n "$x" ] && _ap+=("$x"); done
    /usr/local/bin/opsgate access "${_ap[@]}" --yes || warn "could not set access profiles: $ACCESS (staying read-only)"
  elif { : </dev/tty; } 2>/dev/null; then
    /usr/local/bin/opsgate access || true     # the menu: the owner picks what the AI may do
  else
    info "${D}Access: read only. To allow more: sudo opsgate access${N}"
  fi
fi
ok "writable: $(grep -c . "$ETC/write-paths" || true) folder(s) · restartable: $(grep -c . "$ETC/restart-services" || true) service(s)"
info "${D}Later: sudo opsgate access · sudo opsgate allow-write /path · sudo opsgate allow-restart nginx${N}"

# ------------------------------------------------------------------ service
step "Starting the agent"
sed "s#__DOCS_URL__#$CLOUD_URL/docs#" "$APP/deploy/opsgate.service" > /etc/systemd/system/opsgate.service
install -d -m 755 /etc/systemd/system/opsgate.service.d
if [ "$BIND" = 172.18.0.1 ]; then
  cat > /etc/systemd/system/opsgate.service.d/bind.conf <<'EOF'
[Unit]
After=docker.service
[Service]
# Listens on docker_gwbridge (where EasyPanel's Traefik reaches the host): wait for it at boot.
ExecStartPre=/bin/sh -c 'for i in $(seq 1 60); do [ -e /sys/class/net/docker_gwbridge ] && exit 0; sleep 2; done; exit 0'
EOF
else rm -f /etc/systemd/system/opsgate.service.d/bind.conf; fi
systemctl daemon-reload
systemctl enable -q "$UNIT"
systemctl restart "$UNIT"
for _ in $(seq 1 30); do ss -ltn | grep -q "$BIND:$PORT " && break; sleep 1; done
if ! systemctl is-active -q "$UNIT" || ! ss -ltn | grep -q "$BIND:$PORT "; then
  journalctl -u "$UNIT" -n 30 --no-pager || true
  rollback; systemctl restart "$UNIT" 2>/dev/null || true
  die "The agent did not start (log above). The previous version was restored if there was one."
fi
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://$BIND:$PORT/mcp" -H 'Content-Type: application/json' -d '{}' || true)"
if [ "$code" != 401 ]; then
  journalctl -u "$UNIT" -n 20 --no-pager || true
  rollback; systemctl restart "$UNIT" 2>/dev/null || true
  die "Local check failed (HTTP $code, expected 401). The previous version was restored if there was one."
fi
rm -rf "$APP.old" "$VENV.old"
ok "running as $SVC_USER on $BIND:$PORT, authentication required"

# ------------------------------------------------------------------ HTTPS front
open_firewall() {
  [ "$NO_FIREWALL" = 1 ] && return 0
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ok "ufw: ports 80 and 443 open"
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-service=http --add-service=https && firewall-cmd -q --reload; ok "firewalld: http/https open"
  fi
}

step "Publishing https://$DOMAIN"
case "$PROXY" in
  easypanel)
    "$VENV/bin/python" "$APP/scripts/proxy_route.py" add --file "$EASYPANEL_DIR/custom.yaml" --name opsgate \
      --domain "$DOMAIN" --upstream "http://172.18.0.1:$PORT"
    ok "route added to EasyPanel's Traefik ($EASYPANEL_DIR/custom.yaml, backup kept)" ;;
  caddy)
    if ! have caddy; then
      info "Installing Caddy (automatic HTTPS)"
      if [ "$PKG" = apt ]; then
        pkg_install debian-keyring debian-archive-keyring apt-transport-https gnupg >/dev/null 2>&1 || true
        if curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null \
           && curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt -o /etc/apt/sources.list.d/caddy-stable.list; then
          chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
        fi
        pkg_install caddy || die "Could not install Caddy. Install it (https://caddyserver.com/docs/install) and run this again."
      elif [ "$PKG" = dnf ]; then
        dnf install -y -q 'dnf-command(copr)' >/dev/null 2>&1 || true
        dnf copr enable -y @caddy/caddy >/dev/null 2>&1 || true
        pkg_install caddy || die "Could not install Caddy."
      else die "Install Caddy (https://caddyserver.com/docs/install) and run this again."; fi
      printf '# Caddy configuration. OpsGate adds its site through the import below.\nimport /etc/caddy/opsgate.caddy\n' > /etc/caddy/Caddyfile
    fi
    cat > /etc/caddy/opsgate.caddy <<EOF
# OpsGate Agent — managed by the OpsGate installer
$DOMAIN {
	reverse_proxy $BIND:$PORT {
		flush_interval -1
	}
}
EOF
    if ! grep -qxF 'import /etc/caddy/opsgate.caddy' /etc/caddy/Caddyfile 2>/dev/null; then
      cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
      printf '\nimport /etc/caddy/opsgate.caddy\n' >> /etc/caddy/Caddyfile
    fi
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 || die "Caddy rejected the configuration (caddy validate --config /etc/caddy/Caddyfile)."
    open_firewall
    systemctl enable -q caddy; systemctl reload caddy 2>/dev/null || systemctl restart caddy
    ok "Caddy serves https://$DOMAIN (certificate from Let's Encrypt)" ;;
  nginx)
    SITE=/etc/nginx/sites-available/opsgate; [ -d /etc/nginx/sites-available ] || SITE=/etc/nginx/conf.d/opsgate.conf
    cat > "$SITE" <<EOF
# OpsGate Agent — managed by the OpsGate installer
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        proxy_pass http://$BIND:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
}
EOF
    [ -d /etc/nginx/sites-enabled ] && ln -sf "$SITE" /etc/nginx/sites-enabled/opsgate
    nginx -t >/dev/null 2>&1 || die "nginx rejected the configuration (nginx -t)."
    systemctl reload nginx
    open_firewall
    if ! have certbot; then info "Installing certbot"; pkg_install certbot python3-certbot-nginx || die "Install certbot and run this again."; fi
    if [ -n "$EMAIL" ]; then CB_MAIL=(--email "$EMAIL"); else CB_MAIL=(--register-unsafely-without-email); fi
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos "${CB_MAIL[@]}" --redirect >/dev/null 2>&1 \
      || die "certbot could not get a certificate for $DOMAIN (DNS pointing here? port 80 open?). Run: certbot --nginx -d $DOMAIN"
    ok "nginx serves https://$DOMAIN (certificate from Let's Encrypt, auto-renewed)" ;;
  none)
    warn "No reverse proxy configured (--proxy none or ports 80/443 used by another program)."
    info "Point your HTTPS proxy for $DOMAIN to http://$BIND:$PORT with response buffering off." ;;
esac

if [ "$PROXY" != none ]; then
  info "Waiting for the HTTPS certificate (up to 2 minutes)…"
  code=000
  for _ in $(seq 1 40); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST "https://$DOMAIN/mcp" -H 'Content-Type: application/json' -d '{}' || true)"
    [ "$code" = 401 ] && break; sleep 3
  done
  if [ "$code" = 401 ]; then ok "https://$DOMAIN/mcp answers (authentication required)"
  else warn "https://$DOMAIN is not answering yet (HTTP $code). Certificates can take a few minutes; check later with: sudo opsgate doctor"; fi
fi

step "Linking with OpsGate Cloud"
linked=0
for _ in $(seq 1 15); do
  if [ -f /var/lib/opsgate/meter.json ] && "$VENV/bin/python" -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s.get("last_ok") else 1)' /var/lib/opsgate/meter.json 2>/dev/null; then linked=1; break; fi
  sleep 2
done
[ "$linked" = 1 ] && ok "this server now shows as Online in your dashboard" || warn "no report yet; it usually appears within a few minutes"

# ------------------------------------------------------------------ summary
URL="https://$DOMAIN/mcp"
echo
echo "${G}${B}OpsGate is installed.${N}"
echo
echo "  ${B}Connector URL${N}   $URL"
if [ -n "$PASSWORD" ]; then
  echo "  ${B}Login password${N}  ${Y}${PASSWORD}${N}"
  echo "                  ${D}Shown only now. Save it in your password manager. New one: sudo opsgate password${N}"
fi
echo
echo "  ${B}Next:${N} in Claude open Settings → Connectors → Add custom connector, paste the URL,"
echo "        click Connect and sign in with the password above. ChatGPT, Claude Code and others:"
echo "        $CLOUD_URL/dashboard/connect"
echo
echo "  ${D}The AI can read this server as an unprivileged user and change nothing until you allow it:${N}"
echo "  ${D}  sudo opsgate allow-write /var/www/myapp   ·   sudo opsgate allow-restart nginx   ·   sudo opsgate help${N}"
echo
exit 0
}
