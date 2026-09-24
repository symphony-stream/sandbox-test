#!/bin/bash
# ssbx: prepares the VM. Lima runs this as root at every boot, so everything
# in here has to be safe to run again. Parameters come from ssbx.toml through
# the rendered template (PARAM_*). The read-only share from your machine is
# mounted at /ssbx: the proxy's CA certificate, Claude Code's managed
# settings and the audit hook.
set -eu -o pipefail
export DEBIAN_FRONTEND=noninteractive

PORT="${PARAM_ProxyPort:-17080}"
UPSTREAM="${PARAM_Upstream:-}"
USER_NAME="${PARAM_User:?}"
SHARE=/ssbx
MARK=/var/lib/ssbx
mkdir -p "$MARK" /opt/ssbx /etc/claude-code/managed-settings.d /usr/local/share/ca-certificates

say() { echo "ssbx: $*"; }

# Root reaches the network directly at boot (through your upstream proxy if
# you have one); the sandbox user only ever reaches the ssbx proxy.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
if [ -n "$UPSTREAM" ]; then
  export http_proxy="$UPSTREAM" https_proxy="$UPSTREAM" HTTP_PROXY="$UPSTREAM" HTTPS_PROXY="$UPSTREAM"
fi

# --- packages, once per list ---------------------------------------------
WANT="nodejs npm git curl ca-certificates python3 ripgrep jq nftables less procps openssh-client ${PARAM_Packages:-}"
if [ "$(cat "$MARK/packages" 2>/dev/null || true)" != "$WANT" ]; then
  say "installing packages"
  apt-get update -q
  # shellcheck disable=SC2086
  apt-get install -y -q --no-install-recommends $WANT
  echo "$WANT" > "$MARK/packages"
fi

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

# --- the proxy's certificate, so intercepted hosts look right --------------
if ! cmp -s "$SHARE/ssbx-ca.crt" /usr/local/share/ca-certificates/ssbx-ca.crt; then
  cp "$SHARE/ssbx-ca.crt" /usr/local/share/ca-certificates/ssbx-ca.crt
  chmod 644 /usr/local/share/ca-certificates/ssbx-ca.crt
  update-ca-certificates >/dev/null
fi

# --- Claude Code's managed settings and the audit hook ---------------------
cp "$SHARE/managed-settings.json" /etc/claude-code/managed-settings.json
chmod 644 /etc/claude-code/managed-settings.json
ln -sfn "$SHARE/managed.json" /etc/claude-code/managed-settings.d/50-ssbx.json  # read live, no restart needed
install -m 755 "$SHARE/audit-hook" /opt/ssbx/audit-hook

# --- the user's home: a guest directory with your folders mounted inside ---
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
if [ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] && [ "$(stat -c %U "$HOME_DIR")" != "$USER_NAME" ]; then
  chown "$USER_NAME:" "$HOME_DIR"
fi

# --- no root for the user: the firewall below has to stay ------------------
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  if grep -qE "^(%?$USER_NAME|$USER_NAME|ALL)\b" "$f" 2>/dev/null; then
    rm -f "$f"
  fi
done
for g in sudo wheel admin; do
  if getent group "$g" >/dev/null && id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx "$g"; then
    gpasswd -d "$USER_NAME" "$g" >/dev/null
  fi
done
rm -f "$HOME_DIR/password"
if sudo -l -U "$USER_NAME" 2>/dev/null | grep -qE '\(ALL|may run'; then
  say "warning: $USER_NAME still has sudo rights"
fi

# --- the firewall: only the ssbx proxy on your machine is reachable --------
GATEWAY="$(getent ahostsv4 host.lima.internal | awk '{print $1; exit}')"
[ -n "$GATEWAY" ] || GATEWAY="192.168.5.2"
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# ssbx: written at every boot by provision.sh
flush ruleset
table inet ssbx {
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    ct state established,related accept
    meta skuid 0 accept
    ip daddr $GATEWAY tcp dport $PORT accept
    reject with icmpx type admin-prohibited
  }
}
EOF
nft -f /etc/nftables.conf
systemctl enable nftables.service >/dev/null 2>&1 || true

touch /run/ssbx.ready
say "ready: proxy at $GATEWAY:$PORT, user $USER_NAME without sudo"
