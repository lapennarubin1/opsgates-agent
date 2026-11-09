#!/usr/bin/env bash
# Remove the OpsGate Agent from this server.   sudo opsgate uninstall [--purge]
#   default: removes the service, sudo rules, proxy route, ACLs and the code; keeps /etc/opsgate,
#            the audit log and backups (so a reinstall keeps your password and settings)
#   --purge: removes everything, including the configuration, logs, backups and the opsgate user
set -euo pipefail
PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
ETC=/etc/opsgate; CONF=$ETC/install.conf
conf() { [ -f "$CONF" ] && sed -n "s/^$1=//p" "$CONF" | tail -n1 || true; }
MODE="$(conf PROXY_MODE)"; DOMAIN="$(conf DOMAIN)"

echo "==> Stopping the agent"
systemctl disable --now opsgate 2>/dev/null || true
rm -f /etc/systemd/system/opsgate.service; rm -rf /etc/systemd/system/opsgate.service.d
systemctl daemon-reload 2>/dev/null || true

echo "==> Removing sudo rules and helpers"
rm -f /etc/sudoers.d/opsgate /usr/local/sbin/opsgate-asterisk /usr/local/bin/opsgate

echo "==> Removing folder permissions"
for f in "$ETC/write-paths" "$ETC/read-paths"; do
  [ -f "$f" ] || continue
  while IFS= read -r p; do
    [ -n "$p" ] && [ -e "$p" ] || continue
    setfacl -R -x u:opsgate "$p" 2>/dev/null || true
    [ -d "$p" ] && find "$p" -type d -exec setfacl -d -x u:opsgate {} + 2>/dev/null || true
  done < "$f"
done

echo "==> Removing the HTTPS route ($MODE)"
case "$MODE" in
  easypanel)
    [ -f /etc/easypanel/traefik/config/custom.yaml ] && [ -x /opt/opsgate/venv/bin/python ] && \
      /opt/opsgate/venv/bin/python /opt/opsgate/app/scripts/proxy_route.py remove \
        --file /etc/easypanel/traefik/config/custom.yaml --name opsgate || true ;;
  caddy)
    rm -f /etc/caddy/opsgate.caddy
    [ -f /etc/caddy/Caddyfile ] && sed -i '\#^import /etc/caddy/opsgate.caddy$#d' /etc/caddy/Caddyfile
    systemctl reload caddy 2>/dev/null || true ;;
  nginx)
    rm -f /etc/nginx/sites-enabled/opsgate /etc/nginx/sites-available/opsgate /etc/nginx/conf.d/opsgate.conf
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
    echo "   (the Let's Encrypt certificate for $DOMAIN is left in place; remove with: certbot delete --cert-name $DOMAIN)" ;;
esac

echo "==> Removing the code"
rm -rf /opt/opsgate

if [ "$PURGE" = 1 ]; then
  echo "==> Purging configuration, state, logs and backups"
  rm -rf "$ETC" /var/lib/opsgate /var/log/opsgate /var/backups/opsgate
  userdel opsgate 2>/dev/null || true
  echo "OpsGate was removed completely."
else
  echo "OpsGate was removed. Configuration kept in $ETC (reinstalling reuses it). Remove all: rm -rf $ETC /var/lib/opsgate /var/log/opsgate /var/backups/opsgate"
fi
echo "Also remove this server in your OpsGate dashboard to revoke its license key."
