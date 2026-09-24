#!/bin/sh -e
# Installs the ssbx Lima template and a starter config.yaml. Safe to re-run.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v limactl >/dev/null 2>&1; then
	echo "ssbx needs Lima (limactl not found)." >&2
	echo "  macOS: brew install lima" >&2
	echo "  Linux: install lima, qemu and virtiofsd from your package manager" >&2
	echo "         (or https://github.com/lima-vm/lima/releases)" >&2
	exit 1
fi

mkdir -p "$HOME/.config/ssbx" "$HOME/.lima/_templates"

if [ ! -f "$HOME/.config/ssbx/config.yaml" ]; then
	cp "$here/config.yaml" "$HOME/.config/ssbx/config.yaml"
	echo "wrote $HOME/.config/ssbx/config.yaml (edit it: this is your allowlist)"
fi

# A link, not a copy, so `git pull` in this checkout updates the template.
ln -sfn "$here/ssbx.yaml" "$HOME/.lima/_templates/ssbx.yaml"

echo "ssbx installed. Next:"
echo "  limactl start template:ssbx"
echo "  cd ~/Work/project && limactl shell ssbx"
