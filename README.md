# ssbx

A bare Debian VM that can reach only the hosts you allow, running the
allowlist proxy itself (plain [mitmproxy](https://mitmproxy.org/), no
custom code) as a systemd service; no agent of its own, install yours
inside it, through the proxy.

## Install
Lima: macOS `brew install lima`; Linux: lima, qemu, `virtiofsd` from your
distribution, or [Lima's releases](https://github.com/lima-vm/lima/releases).

```sh
git clone https://github.com/symphony-stream/sandbox-test ~/Work/ssbx && ~/Work/ssbx/install.sh
limactl start template:ssbx
cd ~/Work/project && limactl shell ssbx
# then install your agent inside, e.g.:
sudo apt install -y nodejs npm && sudo npm i -g @anthropic-ai/claude-code
```

Add the agent's config folder to `mounts` in `ssbx.yaml` (see the commented
examples) so its login/settings are shared, then `limactl stop ssbx &&
limactl start ssbx`. Later starts: `limactl start ssbx`. Stop: `limactl
stop ssbx`. Rebuild: `limactl delete ssbx`.

## The allowlist
Edit `~/.config/ssbx/config.yaml` (mitmproxy's own config; comments at the
top explain the syntax). It holds one `block_list` rule: everything not
matching it gets refused. For example, to allow reads on a host:

```yaml
| ~d "^example\.com$" & ~m "^(GET|HEAD)$"
```

Tokens go in via `modify_headers`, which injects a header into matching
requests - no code needed (see the commented examples). `tail -f
~/.config/ssbx/proxy.log` shows every request; a blocked one ends `<< 403
Forbidden`. Add the host as above and the proxy restarts within seconds.

## What it protects
The VM sees only the folders you mount in `ssbx.yaml` - your projects and
whichever agent's config folder you add, login included. The proxy inside
can only reach the hosts you list, never your own machine: an unlisted
host gets a 403 without any connection ever opening. Tokens in
`config.yaml` are visible inside the VM, so prefer narrow ones. `sudo`
inside is normal; the firewall only keeps ordinary tools on the proxy.

## License: MIT, see LICENSE.
