# csbx

A sandbox for a coding agent on a Mac (macOS 13+, Apple Silicon or
Intel): Colima VM, one Incus container inside, one proxy. The container
has no network interface at all. Its only way out is a socket to Squid
in the VM. Squid lets through GET/HEAD to the hosts in `allow.txt`, the
POST that git fetch needs, and anything to api.anthropic.com. So the
agent can hold your credentials and MCP servers and read what you
allow, but `git push` and every POST to GitLab, GitHub or anywhere else
get a 403.

```
Mac   ~/sandbox  (the only shared directory)      ~/.csbx  (this repo, read-only in the VM)
 └─ Colima VM "csbx"      Squid on 127.0.0.1:3128, CA key, allow.txt, access.log
     └─ Incus "csbx"      Debian 13, no eth0, proxy socket 127.0.0.1:3128 -> Squid
                          claude, glab, git, node 24, your MCP servers and tokens
```

Files: `colima.yaml` the VM, `squid.conf` the policy engine, `allow.txt`
the hosts, `profile.yaml` the container. Setup is done once by hand,
below, in about ten minutes.

## 1. Mac: the VM

```sh
brew install colima incus
git clone https://github.com/symphony-stream/sandbox-test ~/.csbx
mkdir -p ~/sandbox ~/.colima/csbx && cp ~/.csbx/colima.yaml ~/.colima/csbx/
colima start csbx
colima ssh -p csbx
```

(If you already keep Colima in `~/.config/colima`, use
`~/.config/colima/csbx/` instead of `~/.colima/csbx/`.)

## 2. VM: Squid, then the container

You are the same user as on the Mac, `sudo` asks no password, the repo
is at `/mnt/csbx`. The CA key stays in `/etc/squid/ca.pem`; only
`ca.crt` goes into the container.

```sh
sudo apt-get update && sudo apt-get install -y squid-openssl
sudo openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -subj /CN=csbx -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout /etc/squid/ca.pem -out /etc/squid/ca.pem
sudo chown root:proxy /etc/squid/ca.pem && sudo chmod 640 /etc/squid/ca.pem
sudo openssl x509 -in /etc/squid/ca.pem -out /etc/squid/ca.crt
sudo /usr/lib/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB && sudo chown -R proxy:proxy /var/spool/squid/ssl_db
sudo install -m 644 /mnt/csbx/squid.conf /mnt/csbx/allow.txt /etc/squid/
sudo install -d /etc/squid/errors && echo 'csbx: %M %U refused (allow.txt)' | sudo tee /etc/squid/errors/ERR_ACCESS_DENIED
sudo install -d /etc/systemd/system/squid.service.d && printf '[Service]\nRestart=on-failure\n' | sudo tee /etc/systemd/system/squid.service.d/csbx.conf
sudo systemctl daemon-reload && sudo squid -k parse && sudo systemctl restart squid
```

Now Incus: let it map your uid into the container, create the profile
from `profile.yaml`, launch the container, hand it the CA.

```sh
echo "root:$(id -u):1" | sudo tee -a /etc/subuid /etc/subgid && sudo systemctl restart incus
sudo install -d -o "$(id -u)" -g "$(id -u)" /var/lib/csbx/claude
incus profile create csbx
sed "s/@USER@/$USER/g; s/@UID@/$(id -u)/g" /mnt/csbx/profile.yaml | incus profile edit csbx
incus launch images:debian/13 csbx -p csbx
incus file push -p /etc/squid/ca.crt csbx/usr/local/share/ca-certificates/csbx.crt
incus exec csbx --env U=$USER --env ID=$(id -u) -- bash
```

## 3. Container: your user, git, node, claude

You are root inside; apt and curl already go through the proxy. Use
`x64` instead of `arm64` on an Intel Mac.

```sh
apt-get update && apt-get install -y ca-certificates sudo git curl xz-utils glab && update-ca-certificates
useradd -u $ID -d /home/$U -s /bin/bash -G sudo $U
cp -n /etc/skel/.bashrc /etc/skel/.profile /home/$U/ && chown $U: /home/$U /home/$U/.bashrc /home/$U/.profile
echo "$U ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$U && chmod 440 /etc/sudoers.d/$U
echo 'Defaults env_keep += "HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy NODE_USE_ENV_PROXY NODE_EXTRA_CA_CERTS SSL_CERT_FILE REQUESTS_CA_BUNDLE"' > /etc/sudoers.d/csbx && chmod 440 /etc/sudoers.d/csbx
git config --system url.https://gitlab.com/.insteadOf git@gitlab.com: && git config --system url.https://github.com/.insteadOf git@github.com: && git config --system --add safe.directory '*'
git config --system credential.https://gitlab.com.helper '!f() { test "$1" = get || return 0; echo username=oauth2; echo "password=$(glab config get token --host gitlab.com)"; }; f'
V=$(curl -fsSL https://nodejs.org/dist/latest-v24.x/ | grep -o 'node-v24[0-9.]*-linux-arm64.tar.xz' | head -1) && curl -fsSL https://nodejs.org/dist/latest-v24.x/$V | tar -xJ -C /usr/local --strip-components=1
su $U -c 'set -o pipefail; curl -fsSL https://claude.ai/install.sh | bash' && test -x /home/$U/.local/bin/claude
exit
incus snapshot create csbx clean && exit
```

Node 24 replaces Debian's Node 20 because only 22.21+ sends `fetch()`
through the proxy. The `clean` snapshot is what `csbx reset` restores.

## 4. Mac: the csbx command

Add to `~/.zshrc` (or `~/.bashrc`) and open a new terminal:

```sh
csbx() {
  case "${1:-}" in
    reload) colima ssh -p csbx -- sudo sh -c 'squid -k parse -f /mnt/csbx/squid.conf && install -m 644 /mnt/csbx/squid.conf /mnt/csbx/allow.txt /etc/squid/ && systemctl reload-or-restart squid' ;;
    log)    colima ssh -p csbx -- sudo tail -n 30 -f /var/log/squid/access.log ;;
    reset)  incus snapshot restore colima-csbx:csbx clean ;;
    *)      local h; h=$(incus exec colima-csbx:csbx -- getent passwd "$(id -u)" | cut -d: -f6)
            incus exec colima-csbx:csbx --user "$(id -u)" --group "$(id -u)" \
              --env HOME="$h" --cwd "$h/sandbox/${1:-}" -t -- bash -l ;;
  esac
}
```

## Use

`csbx project` opens a shell in the container in `~/sandbox/project`, as
your user (`csbx` alone: in `~/sandbox`). Get code in with `git clone`
inside. Run `claude` there; on first start pick the login, open the URL
on the Mac, paste the code back. Claude Code's login, settings and MCP
servers and glab's login live in `~/.claude`, which is a disk in the VM
and survives `csbx reset`. glab, with a read-only token, also gives git
its password for gitlab.com:

```sh
glab auth login --hostname gitlab.com --git-protocol https --token glpat-...   # scopes: read_api, read_repository
```

Tokens for MCP servers go into `~/.claude/settings.json`
(`"env": {"GITLAB_TOKEN": "..."}`); Claude Code passes them to the
servers it starts. Give the agent read-only tokens where the service has
them: the proxy blocks writes, a scoped token blocks them twice. More
tools: `sudo apt-get install`, `npm i -g`, `pip` in a venv all go
through the proxy and work for hosts in `allow.txt`; anything installed
outside `~/sandbox` and `~/.claude` is gone after `csbx reset`.

`csbx log` shows every request URL, not headers or bodies. Refused ones
look like `TCP_DENIED/403 POST https://gitlab.com/api/v4/...` or, for an
unlisted host, `TCP_DENIED/200 CONNECT evil.example:443` followed by a
403. Inside the container a refused request gets a one-line 403 body.
"Connection reset" or "Proxy CONNECT aborted" means Squid is down:
`csbx reload`. The first request right after a reload may fail once.

## Allowlist

`allow.txt`: one host per line, `.host` for the host and all subdomains,
GET and HEAD only. Edit it on the Mac, then `csbx reload`. Everything
else is in `squid.conf`: the POST exceptions (`post_ok`: git fetch on
gitlab.com/github.com, Claude Code token refresh) and the any-method
host (`any_ok`: api.anthropic.com). To allow a POST somewhere, put the
host in `allow.txt`, add `acl post_ok url_regex ^https://host\.example/path$`
to `squid.conf`, `csbx reload`.

Refused by design: `git push` (403), ssh (no network), GraphQL and
MCP-over-HTTP (POST), `glab api graphql`, npm audit.

## What it protects, and what you must not do

The container cannot reach anything but Squid, cannot reach the VM, the
Mac or the LAN, has no DNS (Squid resolves listed hosts only), and cannot
change the policy: `allow.txt`, `squid.conf` and the CA key live in the
VM. Root inside the container changes nothing about that.

Not covered: api.anthropic.com takes any request, including ones that
make Anthropic's servers fetch or call other URLs, and data can leave
inside GET requests to allowed hosts. Some APIs accept writes as GET;
read-only tokens close that. `csbx reset` restores the `clean` snapshot
but does not touch `~/sandbox` or `~/.claude`, so after a session you
do not trust, check `~/.claude/settings.json` for hooks you did not add.

The agent can write anything into `~/sandbox`, and that directory is
yours. A planted `.git/config`, `.claude/settings.json`, `.mcp.json` or
`package.json` script runs on the Mac the moment you run git, Claude
Code or a build there, and a git-aware shell prompt runs git on every
`cd`. So: do not enter `~/sandbox` on the Mac. Take code out with
`git fetch ~/sandbox/project branch` into a clone of your own and review
the diff.

## Update, stop, remove

`git -C ~/.csbx pull && csbx reload` applies a new `squid.conf` or
`allow.txt`; a new `profile.yaml` needs the `sed | incus profile edit`
line from step 2 again; a new `colima.yaml` needs copying again and
`colima restart csbx`. `claude update` works inside, `csbx reset` undoes
it; to rebuild the container from scratch: `incus delete -f
colima-csbx:csbx`, then steps 2 (from `incus launch`) and 3. Stop:
`colima stop csbx`. Remove: `colima delete csbx` (`~/sandbox` stays).
License: MIT.
