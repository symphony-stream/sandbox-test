#!/bin/bash
# ssbx: prepares the VM. Lima runs this as root at every boot, so everything
# here has to be safe to run again. /ssbx is the read-only share from your
# machine: the proxy's CA cert, managed settings and the audit hook. Sudo
# stays (the Lima default) - the boundary is the VM, not the user in it.
set -eu -o pipefail
export DEBIAN_FRONTEND=noninteractive

PORT="${PARAM_ProxyPort:?}"
MARK=/var/lib/ssbx
mkdir -p "$MARK" /opt/ssbx /etc/claude-code/managed-settings.d /usr/local/share/ca-certificates

say() { echo "ssbx: $*"; }

# --- the proxy's certificate, so intercepted hosts (incl. apt's) verify ----
if ! cmp -s /ssbx/ssbx-ca.crt /usr/local/share/ca-certificates/ssbx-ca.crt; then
  cp /ssbx/ssbx-ca.crt /usr/local/share/ca-certificates/ssbx-ca.crt
  chmod 644 /usr/local/share/ca-certificates/ssbx-ca.crt
  update-ca-certificates >/dev/null
fi

# --- apt and sudo go through the proxy too, before any apt-get below -------
GATEWAY="$(getent ahostsv4 host.lima.internal | awk '{print $1; exit}')"
[ -n "$GATEWAY" ] || GATEWAY="192.168.5.2"
printf 'Acquire::http::Proxy "http://%s:%s";\nAcquire::https::Proxy "http://%s:%s";\n' \
  "$GATEWAY" "$PORT" "$GATEWAY" "$PORT" > /etc/apt/apt.conf.d/00ssbx
echo 'Defaults env_keep += "HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY SSL_CERT_FILE NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE"' \
  > /etc/sudoers.d/ssbx
chmod 440 /etc/sudoers.d/ssbx

# --- packages, once per list (nodejs/npm and nftables need to land before ---
# --- the npm config and the firewall below can use them) -------------------
WANT="nodejs npm git curl ripgrep jq nftables ca-certificates ${PARAM_Packages:-}"
if [ "$(cat "$MARK/packages" 2>/dev/null || true)" != "$WANT" ]; then
  say "installing packages"
  apt-get update -q
  # shellcheck disable=SC2086
  apt-get install -y -q --no-install-recommends $WANT
  echo "$WANT" > "$MARK/packages"
fi
npm config set proxy "http://$GATEWAY:$PORT" --global
npm config set https-proxy "http://$GATEWAY:$PORT" --global

# --- the firewall: every uid, root included, may reach only the proxy -----
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# ssbx: written at every boot by provision.sh
flush ruleset
table inet ssbx {
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr $GATEWAY tcp dport $PORT accept
    reject with icmpx type admin-prohibited
  }
}
EOF
nft -f /etc/nftables.conf
systemctl enable nftables.service >/dev/null 2>&1 || true

# --- Claude Code, installed once and refreshed at most once a day ----------
if [ ! -f "$MARK/claude" ] || [ -n "$(find "$MARK/claude" -mmin +1440 2>/dev/null)" ]; then
  say "installing Claude Code"
  if npm install -g --no-fund --no-audit @anthropic-ai/claude-code; then
    touch "$MARK/claude"
  else
    say "could not install Claude Code now, will try again at the next start"
    [ -x /usr/local/bin/claude ] && touch "$MARK/claude" || true
  fi
fi

# --- Claude Code's managed settings and the audit hook ---------------------
cp /ssbx/managed-settings.json /etc/claude-code/managed-settings.json
chmod 644 /etc/claude-code/managed-settings.json
ln -sfn /ssbx/managed.json /etc/claude-code/managed-settings.d/50-ssbx.json  # read live, no restart needed
install -m 755 /ssbx/audit-hook /opt/ssbx/audit-hook

touch /run/ssbx.ready
say "ready: proxy at $GATEWAY:$PORT"
