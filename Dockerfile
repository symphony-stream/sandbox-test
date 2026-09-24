# Two images for ssbx, both built from this file by the ssbx script:
#
#   proxy   the only way out of the sandbox. Holds your tokens, lets only
#           read requests through to the hosts in your hosts file, writes
#           the audit log.
#   agent   the sandbox itself: the shell you get from `ssbx`, with git and
#           Claude Code. It has no tokens.


# ---------------------------------------------------------------- proxy

FROM mitmproxy/mitmproxy:12.2.3 AS proxy

# The user the proxy runs as: yours, so the audit log on your machine is yours.
ARG UID=1000
ARG GID=1000

# A certificate authority of our own, created once when the image is built.
# With it the proxy can look inside HTTPS requests to the hosts in your hosts
# file. The agent image below trusts it; the private key stays in this image.
# It lives outside ~/.mitmproxy, which the base image declares as a volume.
RUN python3 -c "from pathlib import Path; from mitmproxy.certs import CertStore; CertStore.from_store(Path('/opt/ssbx/ca'), 'mitmproxy', 2048)" \
    && test -s /opt/ssbx/ca/mitmproxy-ca.pem \
    && test -s /opt/ssbx/ca/mitmproxy-ca-cert.pem \
    && chown -R "$UID:$GID" /opt/ssbx/ca \
    && chmod 700 /opt/ssbx/ca

COPY proxy/addon.py proxy/start /opt/ssbx/
RUN chmod 755 /opt/ssbx/start

# Show log lines right away in `docker logs`.
ENV PYTHONUNBUFFERED=1
ENV HOME=/tmp

USER $UID:$GID
ENTRYPOINT ["/opt/ssbx/start"]


# ---------------------------------------------------------------- agent

FROM debian:trixie-slim AS agent

# Fail the build if a command in a pipe fails (curl | bash below).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Tools the agent usually needs. Add your own with `packages` in the config.
ARG PACKAGES=""
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
       ca-certificates curl gh git jq less nodejs npm procps python3 ripgrep $PACKAGES \
    && rm -rf /var/lib/apt/lists/*

# Trust the proxy's certificate authority. It is copied from the ssbx-proxy
# image, which the ssbx script builds first.
COPY --from=ssbx-proxy /opt/ssbx/ca/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/ssbx-proxy.crt
RUN update-ca-certificates

# The project is mounted from your machine. Without this git refuses to work in
# a directory that belongs to another user.
RUN git config --system --add safe.directory '*'

# Claude Code itself, installed for everyone in /usr/local/bin. The installer
# puts it into $HOME, so we run it with a temporary HOME and copy the binary out.
RUN HOME=/tmp/claude-install bash -c "curl -fsSL https://claude.ai/install.sh | bash" \
    && cp -L /tmp/claude-install/.local/bin/claude /usr/local/bin/claude \
    && rm -rf /tmp/claude-install

# The audit hook (see sandbox/) and the managed settings that wire it into
# Claude Code. Managed settings win over everything else, so the log stays on
# whatever the settings inside say. The ssbx script adds a drop-in with the
# permission mode from your config.
COPY sandbox/audit-hook /opt/ssbx/
COPY sandbox/managed-settings.json /etc/claude-code/managed-settings.json
RUN python3 -m json.tool /etc/claude-code/managed-settings.json >/dev/null \
    && chmod 755 /opt/ssbx/audit-hook \
    && mkdir -p /etc/claude-code/managed-settings.d \
    && chmod 755 /etc/claude-code /etc/claude-code/managed-settings.d \
    && chmod 644 /etc/claude-code/managed-settings.json

# The sandbox user is you: same name, uid and home path as on your machine, so
# files it creates in the project are yours, and paths inside your Claude
# settings keep working. Its home is the ssbx-home volume, with your own
# ~/.claude mounted into it by the ssbx script.
ARG UID=1000
ARG GID=1000
ARG USER_NAME=agent
ARG HOME_DIR=/home/agent
RUN (getent group "$GID" >/dev/null || groupadd --gid "$GID" "$USER_NAME") \
    && useradd --uid "$UID" --gid "$GID" --home-dir "$HOME_DIR" --create-home --shell /bin/bash "$USER_NAME"
USER $USER_NAME
WORKDIR $HOME_DIR

# Updates come from `ssbx rebuild`, not from inside the container.
ENV DISABLE_AUTOUPDATER=1

# Everything goes out through the proxy container.
ENV HTTPS_PROXY="http://proxy:8080" HTTP_PROXY="http://proxy:8080"
ENV https_proxy="http://proxy:8080" http_proxy="http://proxy:8080"
ENV NO_PROXY="localhost,127.0.0.1" no_proxy="localhost,127.0.0.1"

# Node and Python tools keep their own list of certificate authorities.
# Point them to the system one, which now includes the proxy's.
ENV NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/ssbx-proxy.crt"
ENV REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
ENV SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
