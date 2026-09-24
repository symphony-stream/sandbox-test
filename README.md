# ssbx

A bare Debian VM that can reach only the hosts you allow, running the
allowlist proxy itself as a systemd service; no agent of its own, install
yours inside it, through the proxy.

## Install

Linux: Lima, QEMU and `virtiofsd` from your distribution, or from
[Lima's releases](https://github.com/lima-vm/lima/releases). macOS: `brew install lima`.

```sh
git clone https://github.com/symphony-stream/ssbx ~/ssbx
mkdir -p ~/.config/ssbx && cp ~/ssbx/ssbx.example.toml ~/.config/ssbx/ssbx.toml && cp ~/ssbx/proxy.py ~/.config/ssbx/
limactl start ~/ssbx/ssbx.yaml
limactl shell ssbx -- sudo apt-get install -y nodejs npm && limactl shell ssbx -- sudo npm i -g @anthropic-ai/claude-code
```

The proxy's env vars and CA certificate are already set VM-wide, so `apt`,
`npm`, `pip` and anything else pick them up on their own. Add the agent's
config folder to `mounts` in `ssbx.yaml` (see the commented examples),
`limactl stop ssbx && limactl start ssbx`, then `limactl shell ssbx claude`.

Later starts: `limactl start ssbx`. Stop: `limactl stop ssbx`. Rebuild: `limactl delete ssbx`.

## The allowlist

Edit `~/.config/ssbx/ssbx.toml` (mode 600, it can hold tokens):

```toml
[hosts."api.github.com"]
kind = "github"
token = "github_pat_xxx"
allow = ["GET,graphql", "POST /repos/*/*/issues/*/comments"]
mutations = ["addComment"]
```

A host is an exact name, or `*.name` for its subdomains. `allow` holds
`"METHODS [PATH]"` entries (GET/POST/PUT/PATCH/DELETE/OPTIONS/git-fetch/
git-push/graphql/*; `*` is one path segment, `**` any number, no path
means every path). `kind` + `token` add the right header (github, gitlab,
atlassian as `email:api-token`, or bearer); a mutation also needs its name
in `mutations`. `allow = "*"` with no token tunnels the connection
(CONNECT host and SNI only); everything else is intercepted with the
proxy's own certificate.

`tail -f ~/.config/ssbx/proxy.log` (or `grep blocked`) shows refusals with
a snippet to paste in; the proxy picks up edits within a few seconds.

## What it protects

The VM sees only the folders you mount in `ssbx.yaml` - your projects, and
whichever agent's config folder you add, login included. The proxy can
only reach the hosts you list, never your own machine. Tokens in
`ssbx.toml` are visible inside the VM, so prefer read-only ones. `sudo`
inside is normal Lima sudo; the firewall only keeps ordinary tools on the proxy.

## License

MIT, see LICENSE.
