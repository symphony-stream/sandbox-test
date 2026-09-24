# ssbx

A sandbox for coding agents: a Colima VM (Incus inside) whose every
connection is captured on your Mac by mitmproxy in local mode and
checked against an allowlist. Nothing in the VM is configured for the
proxy and nothing in it can go around it: the capture happens on your
Mac, in the process that carries the VM's traffic. Your `~/sandbox` and
`~/.claude` are mounted in, so an agent inside works on your projects
with your Claude Code login, settings and skills.

## What to do
```sh
brew install colima incus mitmproxy
git clone https://github.com/symphony-stream/sandbox-test ~/ssbx
mkdir -p ~/sandbox ~/.config/ssbx ~/.colima/ssbx
cp ~/ssbx/config.yaml ~/.config/ssbx/ && cp ~/ssbx/colima.yaml ~/.colima/ssbx/
mitmproxy --set confdir=~/.config/ssbx     # terminal 1: stays open, every request shows here
colima start ssbx                          # terminal 2
```

The first `mitmproxy` run asks macOS to allow the "Mitmproxy Redirector"
network extension: System Settings > General > Login Items & Extensions
> Network Extensions, switch it on, then start mitmproxy again. If it
says local mode is unavailable, install mitmproxy with
`uv tool install mitmproxy` (or pipx) instead of brew.

`mitmdump --set confdir=~/.config/ssbx` is the same proxy as a plain log.
The VM has network only while mitmproxy runs.

## Inside
`colima ssh ssbx` is the VM (Ubuntu, root via sudo, Incus ready). A
container that works on your projects as you:

```sh
incus launch images:debian/13 ssbx
incus config device add ssbx sandbox disk source=$HOME/sandbox path=$HOME/sandbox shift=true
incus config device add ssbx claude  disk source=$HOME/.claude  path=$HOME/.claude  shift=true
incus exec ssbx -- sh -c "curl -sf http://mitm.it/cert/pem -o /usr/local/share/ca-certificates/ssbx.crt && update-ca-certificates && apt-get update && apt-get install -y sudo git curl && useradd -m -u $(id -u) -s /bin/bash -G sudo $USER && echo '$USER ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/$USER"
ssbx() { incus exec ssbx --user "$(id -u)" --group "$(id -g)" --cwd "$PWD" --env HOME="$HOME" -- bash -l; }   # shell rc
```

Then `cd ~/sandbox/project && ssbx`, install your agent, e.g.
`sudo apt install -y nodejs npm && sudo npm i -g @anthropic-ai/claude-code`.
On macOS Claude Code keeps its login in the Keychain, so run `claude`
once inside and log in; the credentials land in the mounted `~/.claude`.

Stop and start: `colima stop ssbx`, `colima start ssbx`. Remove:
`colima delete ssbx`.

## The allowlist
`~/.config/ssbx/config.yaml` is mitmproxy's own config; the comments at
the top explain the syntax. One `block_list` rule: everything not
matching it gets a 403. To allow reads on a host, add an arm and restart
mitmproxy:

```yaml
| ~d "^example\.com$" & ~m "^(GET|HEAD)$"
```

Tokens go in via `modify_headers` (see the commented examples); they
never enter the VM.

## What it protects
The VM sees only the mounted folders. All of its traffic leaves through
Lima's host agent on your Mac, and mitmproxy captures that process, so
an unlisted host gets a 403 without any connection opening, whatever
runs inside, root included. Keep `network.address` off in colima.yaml:
a reachable IP would give the VM a second, uncaptured path.

## License: MIT, see LICENSE.
