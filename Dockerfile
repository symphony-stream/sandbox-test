# The container Claude Code runs in. claude-sandbox builds it for you.

FROM debian:trixie-slim

# Fail the build if a command in a pipe fails (curl | bash below).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Tools the agent usually needs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl git jq less procps python3 ripgrep \
    && rm -rf /var/lib/apt/lists/*

# The project is mounted from your machine. Without this git refuses to work in
# a directory that belongs to another user.
RUN git config --system --add safe.directory '*'

# The agent user gets your uid, so files it creates in the project are yours.
ARG UID=1000
RUN useradd --create-home --uid "$UID" agent
USER agent

# Claude Code itself. ~/.claude is where the claude-sandbox-home volume goes.
RUN curl -fsSL https://claude.ai/install.sh | bash
RUN mkdir /home/agent/.claude

ENV PATH="/home/agent/.local/bin:$PATH"
ENV CLAUDE_CONFIG_DIR="/home/agent/.claude"

# Updates come from `claude-sandbox rebuild`, not from inside the container.
ENV DISABLE_AUTOUPDATER=1
