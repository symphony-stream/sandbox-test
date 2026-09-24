# ssbx

A sandbox for Claude Code, on macOS and Linux.

`ssbx` runs Claude Code in a Lima VM, in the project you are in, with your own
login, settings, skills and MCP servers. The VM can reach only the hosts you
list, and only in the ways you allow: read GitLab but not push, read Confluence
but write only comments, and so on. Everything the agent does, and everything
it was refused, ends up in a JSON log on your machine.


## How it works

```
your machine                                │  the VM (Lima)
                                            │
  ssbx.toml ──► ssbx ──► proxy (mitmproxy) ◄┼── claude, git, npm, curl ...
  tokens         │        allowlist,         │    no sudo, no other way out,
                 │        adds tokens,       │    ~/Work and ~/.claude mounted
                 │        audit log          │    at the same paths
                 └────────────────────────────► limactl
```

The **VM** is where you and the agent work. It sees the folders you mount
(`~/Work` by default) and your `~/.claude`, at the same paths as on your
machine, so Claude inside is Claude outside: same login, settings, sessions
and history. The user in the VM has no `sudo`, and a firewall lets nothing out
except connections to the proxy.

The **proxy** runs on your machine and holds your tokens. It refuses every
host that is not in `ssbx.toml` and every request an `allow` entry does not
cover. For hosts with a token it adds the token to the requests it lets
through, so the token never enters the VM.


## Install

You need Lima, mitmproxy and Python 3.11 or newer.

macOS:

```sh
brew install lima mitmproxy python
```

Linux: Lima and QEMU from your distribution or from
[Lima's releases](https://github.com/lima-vm/lima/releases), mitmproxy with
`uv tool install mitmproxy` or `pipx install mitmproxy`. For fast file
sharing also install `virtiofsd` (Arch: `pacman -S virtiofsd`, Debian:
`apt install virtiofsd`); without it ssbx falls back to the slower 9p.

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
the proxy, creates the VM (a Debian image is downloaded once, then a couple of
minutes of provisioning) and opens Claude Code in your project. Later runs
take a few seconds.

| command | what it does |
|---|---|
| `ssbx` | Claude Code in the project you are in |
| `ssbx shell`, `ssbx git log` | a shell, or any command, in the VM |
| `ssbx status` | what is running and where the files are |
| `ssbx logs`, `ssbx logs blocked` | follow the audit log, or only the refusals |
| `ssbx check POST https://host/path` | would the proxy let this through? |
| `ssbx reload` | restart the proxy after editing the hosts |
| `ssbx stop` | stop the VM and the proxy |
| `ssbx rebuild` | delete the VM and make it again; the config stays |

The project has to be inside one of your `mounts`. Git worktrees work as long
as the main repository is mounted too. On Linux you are logged in already, the
login file in `~/.claude` is shared; on macOS the login lives in the Keychain,
so Claude asks once and the file it then writes stays in your `~/.claude`.


## Configuration

One file: `~/.lima/_config/ssbx.toml` (`~/.lima` is `$LIMA_HOME` if you set
it). It holds your tokens, keep it at mode 600. The top holds the VM settings;
`cpus`, `memory`, `disk`, `mounts` and `packages` take effect after
`ssbx stop`, the rest right away or at the next Claude session.

```toml
mounts = ["~/Work"]
cpus = 4
memory = 8
permission_mode = "bypassPermissions"
log = "all"                                # or "blocked"
#proxy = "http://proxy.example.com:3128"   # an upstream proxy, if you need one
```

The rest of the file is the allowlist: where the sandbox may go. Everything
not listed is refused.

```toml
[hosts."api.anthropic.com"]
allow = "*"

[hosts."registry.npmjs.org"]
allow = "GET"

[hosts."github.com"]
kind = "github"
token = "github_pat_xxx"
allow = ["GET,git-fetch", "git-push /me/scratch"]

[hosts."*.githubusercontent.com"]
allow = "GET"

[hosts."api.github.com"]
kind = "github"
token = "github_pat_xxx"
allow = ["GET,graphql", "POST /repos/*/*/issues/*/comments"]
mutations = ["addComment"]

[hosts."example.atlassian.net"]
kind = "atlassian"
token = "you@example.com:ATATT3xxx"
allow = ["GET", "POST /wiki/api/v2/footer-comments", "POST /rest/api/3/search/jql"]
```

- A host is an exact name or `*.name` for its subdomains. An exact entry wins
  over a wildcard one.
- `allow` holds entries of `"METHODS [PATH]"`. METHODS, separated by commas:
  `GET` (with HEAD), `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `git-fetch`
  (clone, fetch, pull), `git-push`, `graphql` (queries only), or `*` for
  everything. PATH: `*` is one path segment, `**` any number of them, no PATH
  means every path, the query string is never looked at. For `git-fetch` and
  `git-push` the PATH is the repository.
- Entries only allow, in any order: a request passes if one of them fits.
  `POST` does not allow a push or a GraphQL mutation; those need `git-push`,
  `mutations` or `*`.
- `kind` and `token` make the proxy add the token: `github`, `gitlab`,
  `atlassian` (`email:api-token`) or `bearer`. Give it tokens with only the
  permissions you mean to use.
- A host with only `allow = "*"` and no token is a plain tunnel: the proxy sees
  the host and port, nothing else. Every other host is intercepted with the
  proxy's own certificate, which the VM trusts, so the proxy can look at the
  method and path.

Some things no entry can switch on: your own machine and network, ports other
than 80 and 443, WebSockets, plain HTTP to a host with a token, the endpoints
that hand out credentials (`/jwt/`, `/oauth/`, ...), paths that hide dots or
slashes in percent-encoding, and any GraphQL document the proxy cannot read.

When something is refused, `ssbx logs blocked` shows why and prints the
snippet that would allow it:

```
11:27:07  proxy    BLOCKED       POST example.atlassian.net/wiki/api/v2/pages/123/footer-comments  (POST ... is not allowed)
          to allow it, add to ssbx.toml:
            [hosts."example.atlassian.net"]
            allow = "POST /wiki/api/v2/pages/*/footer-comments"
```

Paste it, run `ssbx reload`, done. `ssbx check METHOD URL` answers the same
question ahead of time.


## The audit log

`~/.lima/_config/ssbx/audit.jsonl` (or `log_file`), one JSON object per line.
The proxy logs what it refused and what it let through; Claude Code inside
reports its sessions, prompts, tool calls and refusals through a hook. With
`log = "blocked"` only refusals and failures are reported. `ssbx logs` follows
it readably; the raw file is there for `jq`.

The log is written by the proxy on your machine. The VM can add events to it
through the proxy, but cannot read or change it. Claude started with `--bare`,
or signed in to an organization whose server-side settings replace the local
managed settings, does not run the hook; the proxy's own events are there anyway.


## What it protects, and what not

The boundary is the VM. Inside it the agent is an ordinary user without
`sudo`; a firewall, set at every boot, rejects everything that is not a
connection to the proxy, and nothing the VM listens on is exposed on your
machine. The proxy is the only way out and it enforces the allowlist. Your
tokens are only on your machine, in `ssbx.toml` and in the proxy's memory.

Things to know:

- Everything in the mounted folders is writable from the VM. That includes
  `.git/hooks`, Makefiles and `package.json` scripts, which run on your machine
  the next time you use git, make or npm there; and `~/.claude`, where an agent
  could change your settings, add a hook or an MCP server that then also applies
  on your machine. With `log = "all"` every write is in the audit log.
- Hosts that are tunnels (`allow = "*"`) are not looked at. Anything the agent
  can send to Anthropic it can send there.
- A token that can write lets the agent write through the allowed endpoints
  only, but a read token is still the safer choice.
- On Linux, QEMU 10.2 and newer crash under load with io_uring; ssbx runs QEMU
  through a small wrapper that turns io_uring off.


## Performance

File sharing is the part that matters. ssbx uses virtiofs (macOS with vz, and
Linux when `virtiofsd` is installed), which is close to native. Without
virtiofsd it falls back to 9p, which is fine for editing but slow for large
`node_modules` or `git status` on big trees. The VM keeps everything it
installs, so `apt` and `npm install -g` inside survive restarts; Claude Code
itself is refreshed at most once a day when the VM starts.


## Moving to another computer

Copy `~/.lima/_config/ssbx.toml` and clone this repository. The VM is made
from scratch on the new machine. `limactl delete ssbx` only removes the VM;
the config stays.


## Files

```
ssbx                 the launcher (Python)
ssbx.example.toml    the config example, copied on the first run
proxy/rules.py       the allowlist: parsing and decisions
proxy/addon.py       the mitmproxy addon around it
vm/ssbx.yaml         the Lima template, filled in from ssbx.toml
vm/provision.sh      what makes the VM at every boot
vm/audit-hook        the Claude Code hook that reports to the log
vm/managed-settings.json  Claude Code's managed settings in the VM
lib/qemu-no-io-uring the QEMU wrapper for Linux
tests/               python3 -m unittest

~/.lima/_config/ssbx.toml    your config and tokens
~/.lima/_config/ssbx/        audit log, proxy log and pid, the proxy's CA,
                             the read-only share the VM sees at /ssbx
~/.lima/_templates/ssbx.yaml the rendered template (limactl start template:ssbx works too)
~/.lima/ssbx/                the VM
```


## License

MIT, see LICENSE.
