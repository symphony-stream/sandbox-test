# ssbx

A sandbox for Claude Code, on macOS and Linux. `ssbx` runs Claude Code in a
Lima VM, in the project you are in, with your own login, settings, skills
and MCP servers. The VM can reach only the hosts you list in one config
file, and only in the ways you allow. Everything blocked, and everything
allowed, ends up in a JSON log on your machine.


## Install

macOS: `brew install lima python`, then `pipx install mitmproxy` or
`brew install mitmproxy`.

Linux: Lima and QEMU from your distribution or from
[Lima's releases](https://github.com/lima-vm/lima/releases); mitmproxy with
`uv tool install mitmproxy` or `pipx install mitmproxy`; Python 3.11+. For
fast file sharing also install `virtiofsd` (Arch: `pacman -S virtiofsd`,
Debian: `apt install virtiofsd`); without it ssbx falls back to the slower
9p.

Then put `ssbx` on your PATH:

```sh
git clone https://github.com/symphony-stream/ssbx ~/ssbx
ln -s ~/ssbx/ssbx ~/.local/bin/ssbx
```


## Use

```sh
cd ~/Work/some-project
ssbx
```

The first run creates `~/.lima/_config/ssbx.toml` from the example, starts
the proxy, creates the VM (a Debian image downloads once, then a couple of
minutes of provisioning) and opens Claude Code in your project. Later runs
take a few seconds. `ssbx <command>` runs any command in the VM instead of
Claude Code (`ssbx bash` for a shell); `ssbx stop` stops the VM and the
proxy; `ssbx logs` / `ssbx logs blocked` follow the audit log. To rebuild
the VM: `limactl delete ssbx`. To see what's running: `limactl list`.

The project has to be inside one of your `mounts`. On Linux you are logged
in already, the login file in `~/.claude` is shared; on macOS the login
lives in the Keychain, so Claude asks once and the file it then writes
stays in your `~/.claude`.


## Configuration

One file: `~/.lima/_config/ssbx.toml` (`~/.lima` is `$LIMA_HOME` if you set
it). It holds your tokens, keep it at mode 600. `cpus`, `memory`, `disk`,
`mounts` and `packages` take effect after `ssbx stop`; the rest at the next
`ssbx` (the proxy restarts on its own when the file changes).

The allowlist is `[hosts."name"]` tables:

```toml
[hosts."api.github.com"]
kind = "github"
token = "github_pat_xxx"
allow = ["GET,graphql", "POST /repos/*/*/issues/*/comments"]
mutations = ["addComment"]
```

- A host is an exact name, or `*.name` for its subdomains.
- `allow` holds `"METHODS [PATH]"` entries (a string, or a list of them).
  METHODS: `GET` (with HEAD), `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`,
  `git-fetch`, `git-push`, `graphql` (queries only), or `*` for everything.
  PATH: `*` is one path segment, `**` any number, no PATH means every path,
  matched fully percent-decoded; the query string is never looked at. A
  request passes if any entry allows it, in any order.
- `kind` + `token` add the right header for you: `github`, `gitlab`,
  `atlassian` (`email:api-token`), or `bearer`. A GraphQL mutation also
  needs its name in `mutations`, or `*` with no `mutations` list at all.
- A host with only `allow = "*"` and no token is a tunnel: the proxy checks
  its CONNECT host and TLS SNI and nothing else, end to end encrypted.
  Every other host is intercepted with the proxy's own certificate, so it
  can look at the method and path.

When something is refused, `ssbx logs blocked` shows why and prints a
snippet you can paste in to allow it - that's how you grow the allowlist,
request by request, instead of writing it all up front.


## What it protects

The VM sees only the folders in `mounts` and your `~/.claude` - your login
included, so Claude inside works exactly as it does outside, and
`~/.claude` is writable from inside too (settings, hooks, whatever an
agent changes there). Your tokens stay on your machine, in `ssbx.toml` and
the proxy's memory; the sandbox itself never sees them. The proxy will not
connect to your own machine, however a host you allow happens to resolve.
Inside the VM you have the normal Lima `sudo`, and a firewall applied to
every uid, root included, keeps ordinary tools on the proxy - not a wall
against a determined root process, just what makes the allowlist actually
apply to them. (If you set an upstream `proxy`, that upstream resolves
names on the sandbox's behalf, so the address check above does not apply
to that traffic.)


## License

MIT, see LICENSE.
