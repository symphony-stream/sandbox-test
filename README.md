# ssbx

A sandbox for AI coding agents such as Claude Code, on macOS and Linux.

`ssbx` opens a shell in a container, in the project you are in. Inside you run
`claude` as usual, with your own settings, skills and MCP servers. The agent can read
your code and your GitLab, GitHub or Jira, fetch and switch branches, but it cannot
push, open merge requests, run pipelines or change anything on those servers. Everything
it does, and everything it was refused, ends up in a JSON log on your machine.


## How it works

```
your project ──► sandbox container ──► proxy container ──► GitLab, Jira, internet
                 no tokens, no sudo,     keeps your tokens,       (through your proxy,
                 no network of its own   lets only reads through,  if you have one)
                                         writes the audit log
```

A Colima VM runs two containers.

The **sandbox** is where you and the agent work. It gets the project you started `ssbx`
in and your `~/.claude`, nothing else from your machine: no `~/.ssh`, no `~/.config`, no
git credentials. Nobody in it can become root. It has no network of its own; everything
goes through the proxy. Your Claude folder is mounted, not copied, so Claude inside is
Claude outside: same login, settings, skills and MCP servers, and its sessions land in
your `~/.claude/projects` like any other.

The **proxy** holds your tokens. For the hosts in your hosts file it lets through only
requests that read: GET requests, `git clone` and `git fetch`, Jira searches. A
`git push`, or any POST, PUT, PATCH or DELETE (a merge request, a comment, a pipeline
run) gets a 403. It adds your token to the requests it lets through, so the token
never enters the sandbox. All other hosts, like Anthropic, npm or PyPI, are passed
through as they are, encrypted end to end. GitHub's GraphQL API, which `gh` uses,
is let through as long as the query does not contain a mutation.

That makes two locks. The token you give the proxy should be read-only, so the server
refuses writes. And the proxy refuses them before they reach the server, even if the
token could write.


## Install

On macOS:

```sh
brew install colima docker docker-buildx
```

On Linux you need QEMU, OpenSSH, the Docker CLI, Colima and Lima. On Arch, for example:

```sh
sudo pacman -S qemu-base openssh docker
mise use -g colima lima    # or download both from their GitHub releases
```

Then put `ssbx` on your PATH:

```sh
git clone https://github.com/symphony-stream/ssbx ~/ssbx
mkdir -p ~/.local/bin
ln -s ~/ssbx/ssbx ~/.local/bin/ssbx
```

`~/.local/bin` has to be on your PATH. On macOS it usually is not, so either add it or
link `ssbx` into a directory that is, such as `/opt/homebrew/bin`.

Your two files, `config` and `hosts`, live in the `ssbx` profile folder of Colima, next
to the VM's own `colima.yaml`: `~/.config/colima/ssbx/` on Linux, `~/.colima/ssbx/` on
macOS (`$COLIMA_HOME/ssbx/` if you set that; `ssbx status` prints the path). Copy the
examples there:

```sh
mkdir -p ~/.config/colima/ssbx        # macOS: ~/.colima/ssbx
cp ~/ssbx/config.example ~/.config/colima/ssbx/config
cp ~/ssbx/hosts.example ~/.config/colima/ssbx/hosts
chmod 600 ~/.config/colima/ssbx/hosts
```

One thing to know: `colima delete ssbx` deletes that folder, config and hosts file
included. `ssbx` never runs it. If you do, keep a copy of the hosts file first.


## Use

```sh
cd ~/some-project
ssbx          # a shell in the sandbox, in this directory
claude        # inside: Claude Code
```

The first run creates the VM and builds both containers. That takes a few minutes.
After that `ssbx` opens in a couple of seconds. On Linux you are already logged in,
the login file in `~/.claude` is shared. On macOS the login lives in the Keychain, which
the sandbox cannot see, so Claude asks once; the file it then writes stays in your
`~/.claude`.

The sandbox gets the git repository you are in (or the current directory if there is
none), mounted at the same path as on your machine. Any project will do, as long as it
is somewhere under your home directory; that is the only folder the VM can see, and
`mounts` in the config changes it.

Other commands:

```sh
ssbx claude       # run one command instead of opening a shell (ssbx -- cmd if cmd is a word below)
ssbx logs         # the audit log, live
ssbx logs blocked # only what was refused
ssbx status       # is the VM running, are the images built, where is everything
ssbx reload       # stop the proxy; it starts again with the current settings next time
ssbx rebuild      # rebuild both containers, which also updates Claude Code
ssbx stop         # stop the VM
```


## Configuration

Everything is in `config` in the Colima profile folder. It is a small bash file;
`config.example` lists every setting with its default. The ones you are most likely to
touch:

```sh
proxy="http://host.docker.internal:1080"   # a proxy for everything leaving the sandbox
permission_mode="bypassPermissions"        # how Claude inside handles permissions
packages=(build-essential golang)          # extra Debian packages for the sandbox
mounts=("$HOME")                           # what the VM may see
```

**Proxy.** Set `proxy` if the sandbox needs one to reach Anthropic, npm and the rest.
Write `host.docker.internal` for a proxy on your own machine; `localhost` would mean
the container itself. The proxy has to speak HTTP (`http://host:port`, with
`user:pass@` if it needs a login); SOCKS does not work. If `HTTPS_PROXY` is set in your
shell, it is the default. The VM uses it for its own downloads too, from the next
`ssbx stop`. With a proxy in between, the proxy resolves names, so a public name that
points at your local network is not caught; without one, it is.

**Your Claude Code.** `~/.claude` and `~/.claude.json` are mounted into the sandbox at
the same path, writable. They are the same files inside and outside, not a copy:
settings, `CLAUDE.md`, skills, plugins, MCP servers, history, and the transcripts of
sessions run inside land in your `~/.claude/projects` like any other. On Linux the
login is shared too, through `~/.claude/.credentials.json`; on macOS log in once inside.
Your home directory has the same path and your user the same id inside as outside, so
absolute paths in your settings keep working.

The other side of this: the agent can change those files. A `settings.json`, a hook or
an MCP server it adds applies on your machine too, and the keys of your MCP servers are
there for it to read. With `log="all"` every Write and Edit is in the audit log.

**Permissions.** `permission_mode` sets the mode Claude inside starts in:
`bypassPermissions` lets it work on its own, which is what a sandbox is for; `auto`
keeps the classifier; empty means whatever your settings say. It is applied as a
managed setting, so no settings file inside can change it (a flag on the `claude`
command line still can).

**The VM.** `cpus`, `memory`, `disk` and `mounts` take effect after `ssbx stop`. The
default mount is your home directory; the sandbox itself still gets only the project
and `~/.claude`. If `mounts` leaves your home directory out, `~/.claude` is mounted on
its own and `~/.claude.json` stays outside: Colima mounts folders, not files.

After changing the config, just run `ssbx` again. The proxy restarts by itself when the
hosts file or the settings it uses change, and the images are rebuilt when their sources
change; `packages` needs `ssbx rebuild`.


## Tokens

Open `hosts` in the Colima profile folder and add one line per host: the host, the kind
of token and the token. The file explains the kinds. Give read-only tokens:

- GitLab: a token with only `read_api` and `read_repository`.
- GitHub: a fine-grained token with Contents and Metadata set to read.
- Jira and Confluence Cloud: an API token of an account that can only browse.
- Jira and Confluence Data Center: a personal access token of a user who can only view.

Remotes like `git@gitlab.com:group/repo.git` work too: for the hosts in the file, git in
the sandbox fetches them over HTTPS through the proxy.


## The audit log

`~/.local/state/ssbx/audit.jsonl` (or `log_file` in the config) gets one JSON object per
line for everything the proxy sees and everything Claude Code reports about itself:

```json
{"ts":"2026-09-24T09:01:12.410Z","source":"proxy","event":"blocked","method":"POST","host":"gitlab.com","path":"/api/v4/projects/1/merge_requests","reason":"POST /api/v4/projects/1/merge_requests would change something, only reading is allowed"}
{"ts":"2026-09-24T09:01:12.415Z","source":"sandbox","event":"tool_failed","session":"…","cwd":"/home/you/project","tool":"Bash","input":{"command":"glab mr create …"},"error":"…403 Blocked by the ssbx proxy…"}
```

| event | source | what it is |
|---|---|---|
| `blocked` | proxy | a write to a host from your hosts file, refused |
| `allowed` | proxy | a read from a host from your hosts file, with your token added |
| `passthrough` | proxy | a connection to any other host (Anthropic, npm), not inspected |
| `denied` | sandbox | Claude's own classifier (auto mode) refused a tool call |
| `asked` | sandbox | Claude had to ask for permission |
| `tool_failed` | sandbox | a tool call failed, for example with a 403 from the proxy |
| `tool` | sandbox | a tool call: the command, the file, the pattern |
| `prompt` | sandbox | what you typed |
| `session_start`, `session_end` | sandbox | a Claude session |

`source` says who reported the event. The proxy sees the network for itself. The
`sandbox` events come from hooks that Claude Code runs inside; they are as honest as the
sandbox, which cannot read or change the log. With `log="blocked"` in the config the
`tool` and `prompt` events are left out.

`ssbx logs` follows the file and prints one readable line per event; `ssbx logs
blocked` only the refusals. The raw file is there for `jq`.


## Moving to another computer

Install Colima and Docker as above, clone the repository, copy `config` and `hosts`
from the Colima profile folder into the same place on the new machine. That is all; the
rest is built on the first run.


## What it does not protect you from

The agent can change any file in the project, including `.git/hooks`, the Makefile
and `package.json` scripts. Those run on your machine the next time you use git, make
or npm there. Look at what changed before you do.

Hosts on the internet that are not in your hosts file are reachable without restrictions,
so anything the agent reads can leave through them. What it cannot do is use your tokens
there, or reach your machine, the VM or your local network: the proxy refuses private
addresses and ports other than 80 and 443. The `passthrough` events in the log show where
it connected.

Your `~/.claude` and `~/.claude.json` are the agent's to read and change, keys of MCP
servers included (see Configuration). Give those servers keys that can only read.

The `sandbox` events in the log are reported by Claude Code's hooks inside. Claude
started with `--bare`, or signed in to an organization whose server-side settings replace
the local managed settings, does not run them; the proxy's own events are there anyway.


## Files

- `ssbx`: the script you run.
- `Dockerfile`: both containers.
- `proxy/addon.py`: the rules, and the log; `proxy/start` starts it.
- `sandbox/`: the hook that reports Claude's events and the managed settings that wire
  it in.
- `lib/qemu-no-io-uring`: on Linux, a wrapper that keeps QEMU 10.2 and later from
  crashing under network load. `lib/logs` prints the log.
- `config.example`, `hosts.example`: your two files, documented.


## License

MIT
