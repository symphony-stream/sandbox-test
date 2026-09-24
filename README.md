# ssbx

A sandbox for coding agents: a Colima VM with an Incus container inside.
The container has no network device at all; its only way out is an
allowlist proxy (plain [mitmproxy](https://mitmproxy.org/), no custom
code) running in the VM. Your `~/sandbox` and `~/.claude` are mounted
into the container at the same paths, so the agent inside works on your
projects with your Claude Code login, settings and skills.

## Install
macOS: `brew install colima incus`. Linux: colima and the incus client
from your package manager.

```sh
git clone https://github.com/symphony-stream/sandbox-test ~/ssbx
mkdir -p ~/sandbox ~/.config/ssbx ~/.colima/ssbx
cp ~/ssbx/config.yaml ~/.config/ssbx/ && cp ~/ssbx/colima.yaml ~/.colima/ssbx/
colima start ssbx            # Linux: add --vm-type qemu --mount-type 9p
incus list                   # wait until ssbx is RUNNING (first start downloads the image)
```

To work inside as yourself, put this in your shell rc:

```sh
ssbx() { incus exec ssbx --user "$(id -u)" --group "$(id -g)" --cwd "$PWD" --env HOME="$HOME" -- bash -l; }
```

Then `cd ~/sandbox/project && ssbx`, and install your agent inside, e.g.
`sudo apt install -y nodejs npm && sudo npm i -g @anthropic-ai/claude-code`.
On macOS Claude Code keeps its login in the Keychain, so run `claude`
once inside and log in; the credentials land in the mounted `~/.claude`
and survive rebuilds. `incus shell ssbx` gives a root shell.

Stop and start: `colima stop ssbx`, `colima start ssbx`. Rebuild the
container: `incus delete -f ssbx && colima restart ssbx`. Remove
everything: `colima delete ssbx`.

## The allowlist
Edit `~/.config/ssbx/config.yaml` (mitmproxy's own config; the comments
at the top explain the syntax). It holds one `block_list` rule:
everything not matching it gets a 403. To allow reads on a host, add an
arm to the list:

```yaml
| ~d "^example\.com$" & ~m "^(GET|HEAD)$"
```

Tokens go in via `modify_headers` (see the commented examples).
`tail -f ~/.config/ssbx/proxy.log` shows every request; a blocked one
ends `<< 403 Forbidden`. Add the host and the proxy restarts within
seconds.

## What it protects
The container sees only the mounted folders. It has no network device;
port 8080 inside is the proxy in the VM, which reaches only the hosts
you list and never your machine (an unlisted host gets a 403 without any
connection opening). Root inside the container cannot change that: the
proxy and the VM are outside it. `config.yaml` with its tokens is
mounted into the VM only, not into the container.

## License: MIT, see LICENSE.
