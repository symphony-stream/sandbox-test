# ssbx

A sandbox for coding agents. mitmproxy runs on your machine with an
allowlist; a Colima VM (with Incus inside) can reach the internet only
through it: the VM trusts the proxy's CA, points every tool at it and
refuses any other route out, containers included. Your `~/sandbox` and
`~/.claude` are mounted into the VM and into the `ssbx` container at the
same paths, so an agent inside works on your projects with your Claude
Code login, settings and skills.

## Install
macOS: `brew install colima incus mitmproxy`. Linux: the same three from
your package manager.

```sh
git clone https://github.com/symphony-stream/sandbox-test ~/ssbx
mkdir -p ~/sandbox ~/.config/ssbx ~/.colima/ssbx
cp ~/ssbx/config.yaml ~/.config/ssbx/ && cp ~/ssbx/colima.yaml ~/.colima/ssbx/
mitmproxy --set confdir=~/.config/ssbx     # terminal 1: the proxy; every request shows up here
colima start ssbx                          # terminal 2 (Linux: --vm-type qemu --mount-type 9p)
incus list                                 # wait until ssbx is RUNNING
```

The proxy must be running before the VM starts (the first start installs
things through it). When it is not running, nothing in the sandbox has
network. `mitmdump --set confdir=~/.config/ssbx` is the same proxy as a
plain log instead of the interactive list.

To work inside the container as yourself, put this in your shell rc:

```sh
ssbx() { incus exec ssbx --user "$(id -u)" --group "$(id -g)" --cwd "$PWD" --env HOME="$HOME" -- bash -l; }
```

Then `cd ~/sandbox/project && ssbx`, and install your agent inside, e.g.
`sudo apt install -y nodejs npm && sudo npm i -g @anthropic-ai/claude-code`.
On macOS Claude Code keeps its login in the Keychain, so run `claude`
once inside and log in; the credentials land in the mounted `~/.claude`.
`incus shell ssbx` gives a root shell; `colima ssh ssbx` the VM itself.

Stop and start: `colima stop ssbx`, `colima start ssbx`. Rebuild the
container: `incus delete -f ssbx && colima restart ssbx`. Remove
everything: `colima delete ssbx`.

## The allowlist
Edit `~/.config/ssbx/config.yaml` (mitmproxy's own config; the comments
at the top explain the syntax) and restart mitmproxy. It holds one
`block_list` rule: everything not matching it gets a 403. To allow reads
on a host, add an arm to the list:

```yaml
| ~d "^example\.com$" & ~m "^(GET|HEAD)$"
```

Tokens go in via `modify_headers` (see the commented examples); they
never enter the VM.

## What it protects
The VM sees only the mounted folders. Its firewall lets out exactly one
thing: connections to the proxy on your machine, which reaches only the
hosts you list (an unlisted host gets a 403 without any connection
opening). Inside the VM you have root and Incus without limits; a root
process there could lift the firewall, but still could not reach your
files beyond the mounts. Tokens stay in the proxy on your machine.

## License: MIT, see LICENSE.
