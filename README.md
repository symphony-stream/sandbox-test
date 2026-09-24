# claude-sandbox

Run Claude Code with `--dangerously-skip-permissions` without giving it your whole machine.

Claude runs in a Docker container inside a Colima VM. The container sees one thing from
your computer: the project directory you started it in. It has no SSH keys, no git
credentials and no access to the rest of your home directory. It works the same way on
macOS and on Linux.

The whole thing is two files: `claude-sandbox`, a shell script, and the `Dockerfile` it builds.


## Install

On macOS:

```sh
brew install colima docker
```

On Linux you need QEMU, the Docker CLI, Colima and Lima. On Arch, for example:

```sh
sudo pacman -S qemu-base docker
mise use -g colima lima    # or download both from their GitHub releases
```

Then put the script on your PATH:

```sh
git clone https://github.com/symphony-stream/claude-sandbox ~/claude-sandbox
ln -s ~/claude-sandbox/claude-sandbox ~/.local/bin/claude-sandbox
```


## Use

Go to a project and start it:

```sh
cd ~/code/some-project
claude-sandbox
```

The first time this creates a Colima VM called `claude-sandbox` and builds the image.
That takes a few minutes. After that it starts in seconds. Your usual Docker context is
not touched.

Other commands:

```sh
claude-sandbox shell      # bash in the same container, to look around
claude-sandbox rebuild    # rebuild the image, which also updates Claude Code
colima stop claude-sandbox
```

The project has to be inside your home directory, because that is what Colima shares
with the VM. Running it in the home directory itself is refused on purpose.


## Logging in and tokens

Anything the agent should have goes into `~/.config/claude-sandbox/env`, one
`NAME=value` per line. For example:

```sh
CLAUDE_CODE_OAUTH_TOKEN=...
GITLAB_TOKEN=glpat-...
JIRA_URL=https://example.atlassian.net
JIRA_EMAIL=you@example.com
JIRA_TOKEN=...
```

`CLAUDE_CODE_OAUTH_TOKEN` comes from running `claude setup-token` on your own machine.
Without it, Claude asks you to log in inside the container. Either way the login is kept
in a Docker volume called `claude-sandbox-home`, so you do it once.


## Why it cannot push or change your GitLab, Jira or Confluence

Because it has nothing to do it with. The only credentials inside the container are the
ones you put in `env`, so give it read-only ones:

- GitLab: a token with only `read_api` and `read_repository`. It can clone and read
  the API. GitLab itself refuses a push or any write with that token.
- Jira and Confluence Cloud: a scoped API token with read scopes only. A classic API
  token can do everything its account can do, so do not use one of those here.
- Jira and Confluence Data Center: a personal access token of a user who can only view.


## What it does not protect you from

The agent can reach the internet. Whatever it reads, including the tokens in `env`, it
could send somewhere else.

It can change any file in the project, including `.git/hooks`, the Makefile and
`package.json` scripts. Those run on your machine the next time you use git, make or
npm. Look at what changed before you do.


## License

MIT
