"""
The ssbx proxy. Everything that leaves the sandbox goes through here.

Hosts from your hosts file (~/.config/ssbx/hosts) are read-only for the sandbox.
Allowed:
  - GET and HEAD requests
  - git clone and git fetch
  - Jira searches, which are POST requests that only read
Blocked:
  - git push
  - every other POST, PUT, PATCH and DELETE: no merge requests, no comments,
    no pipelines, no CI triggers, no issue changes
  - WebSockets, plain HTTP, and the endpoints that hand out other credentials
The proxy adds your token to the requests it lets through. The sandbox itself
never has the token.

All other hosts on the internet (Anthropic, npm, PyPI and so on) are passed
through untouched, encrypted end to end, on ports 80 and 443 only. Your
machine, the VM and your local network are out of reach. If an upstream proxy
is configured, everything goes through it.

Every decision is made when the request headers arrive, before anything is
forwarded. Everything the proxy sees is written to the audit log, one JSON
object per line (SSBX_LOG_FILE), and to stdout for `docker logs`. Claude Code
inside the sandbox reports its own events (tool calls, refusals) to the same
log by posting them to http://ssbx.audit/, a name that exists only here. Those
events carry "source": "sandbox"; the proxy's own carry "source": "proxy".
"""

import asyncio
import base64
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

from mitmproxy import ctx, http, tls


LOG_FILE = os.environ.get("SSBX_LOG_FILE", "")
LOG_MAX_BYTES = 20 * 1024 * 1024  # then the log is rotated once, to <name>.1

# The name the sandbox posts its events to. Never forwarded anywhere.
AUDIT_HOST = "ssbx.audit"
AUDIT_MAX_BYTES = 16 * 1024
AUDIT_MAX_PER_SECOND = 20
AUDIT_BUDGET_BYTES = 4 * 1024 * 1024  # per AUDIT_BUDGET_SECONDS, so a flood cannot push the proxy's own records out
AUDIT_BUDGET_SECONDS = 600


# Read the hosts file. The launcher passes its content in SSBX_HOSTS.
# Each line is: host  kind  token

TOKENS = {}

for line in os.environ.get("SSBX_HOSTS", "").splitlines():
    line = line.strip()
    if line == "" or line.startswith("#"):
        continue
    parts = line.split(None, 2)
    if len(parts) != 3:
        sys.exit(f"ssbx proxy: bad line in the hosts file, expected 'host kind token': {line!r}")
    host, kind, token = parts
    TOKENS[host.lower()] = (kind, token.strip())


# ------------------------------------------------------------------ the log

def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log_event(event):
    """Append one event to the audit log and print it for `docker logs`."""
    event = {"ts": now(), **event}
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace") + b"\n"
    if LOG_FILE:
        try:
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
                os.replace(LOG_FILE, LOG_FILE + ".1")
            with open(LOG_FILE, "ab") as f:
                f.write(line)
        except Exception as e:  # noqa: BLE001
            print(f"ssbx proxy: cannot write {LOG_FILE}: {e}", file=sys.stderr, flush=True)
    sys.stdout.buffer.write(line)
    sys.stdout.flush()


# Query strings can carry tokens (?private_token=...). Their values are not logged.
SECRET_PARAM = re.compile(r"(?i)([^&=]*(token|key|secret|pass|auth|sig)[^&=]*=)[^&]*")


def logged_path(path):
    if "?" not in path:
        return path
    path, query = path.split("?", 1)
    return path + "?" + SECRET_PARAM.sub(r"\1***", query)


# Connections to hosts that are not in the hosts file are logged once per host
# and port every few minutes, not once per connection.
PASSTHROUGH_SEEN = {}
PASSTHROUGH_EVERY = 300


def note_passthrough(host, port, **extra):
    key = (host, port)
    now_s = time.monotonic()
    if extra or now_s - PASSTHROUGH_SEEN.get(key, -PASSTHROUGH_EVERY) >= PASSTHROUGH_EVERY:
        PASSTHROUGH_SEEN[key] = now_s
        log_event({"source": "proxy", "event": "passthrough", "host": host, "port": port, **extra})


# ------------------------------------------------------------------ tokens

def basic_auth(user, password):
    pair = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(pair).decode()


def auth_headers(kind, token, is_git):
    """The header that carries the token, in the form each service expects."""
    if kind == "gitlab":
        if is_git:
            return {"Authorization": basic_auth("oauth2", token)}
        return {"PRIVATE-TOKEN": token}

    if kind == "github":
        if is_git:
            return {"Authorization": basic_auth("x-access-token", token)}
        return {"Authorization": f"Bearer {token}"}

    if kind == "atlassian":
        # token is "you@example.com:api-token"
        email, api_token = token.split(":", 1)
        return {"Authorization": basic_auth(email, api_token)}

    if kind == "bearer":
        return {"Authorization": f"Bearer {token}"}

    raise ValueError(f"unknown kind in hosts file: {kind}")


for _host, (_kind, _token) in TOKENS.items():
    auth_headers(_kind, _token, False)  # fail at startup on a bad kind, not on first use


# ------------------------------------------------------------------ the rules

# Only plain paths are accepted, so a write cannot hide behind something like
# /rest/api/3/issue;/search or a doubled slash.
PLAIN_PATH = re.compile(r"^/$|^(/[A-Za-z0-9._~%+@:,-]+)+/?$")

# git clone and git fetch: /group/repo.git/info/refs and /group/repo.git/git-upload-pack.
# Never under /api/, where GitLab could take the last part for a file name.
GIT_READ = re.compile(r"^(?!/api/)(/[A-Za-z0-9._~-]+)+/(info/refs|git-upload-pack)$")

# Jira searches are POST requests that only read. Exact paths, with an
# optional context path in front for Data Center (/jira/rest/api/2/search).
JIRA_SEARCH = re.compile(r"^(/[A-Za-z0-9._~-]+)?/rest/api/(2|3|latest)/(search(/jql|/approximate-count)?|issue/bulkfetch)$")

GRAPHQL_MUTATION = re.compile(r"\bmutation\b")

# Endpoints that turn the token into other credentials.
CREDENTIAL_PATHS = ("/jwt/", "/oauth/", "/-/", "/login", "/session", "/users/sign_in")


def why_blocked(request, kind):
    """Return the reason to block a request to a host with a token, or None."""
    path = request.path.split("?", 1)[0]
    method = request.method

    if request.scheme != "https":
        return "the token only travels over HTTPS"

    if "upgrade" in request.headers.get("Connection", "").lower() or "Upgrade" in request.headers:
        return "WebSockets are not allowed"

    if not PLAIN_PATH.match(path) or "/../" in path + "/" or "/./" in path + "/":
        return "unusual path"

    if path.startswith(CREDENTIAL_PATHS) or "/jwt/" in path or "/oauth/" in path:
        return "that endpoint hands out credentials"

    if "git-receive-pack" in request.path:
        return "git push is not allowed"

    if method in ("GET", "HEAD"):
        return None

    if method == "POST":
        if GIT_READ.match(path) and path.endswith("/git-upload-pack"):
            return None  # git clone / git fetch
        if kind in ("atlassian", "bearer") and JIRA_SEARCH.match(path):
            return None  # Jira search
        if kind == "github" and path == "/graphql":
            return None  # GitHub GraphQL: the body is checked for mutations in request()

    return f"{method} {path} would change something, only reading is allowed"


# The sandbox may only talk to the internet: not to your machine, the VM or
# the local network, whatever name it uses for them.
PRIVATE_NAMES = {"localhost", "host.docker.internal", "host.lima.internal", "proxy", "ssbx-proxy"}
PRIVATE_SUFFIXES = (".localhost", ".internal", ".local", ".lan", ".home", ".arpa")


def is_private_name(host):
    host = host.lower().rstrip(".").strip("[]")
    if host in PRIVATE_NAMES or host.endswith(PRIVATE_SUFFIXES) or "." not in host:
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


async def resolves_private(host, port):
    """"private" if the name resolves to anything that is not a public address,
    "unresolved" if it cannot be resolved at all, None if it is fine.
    With an upstream proxy the upstream resolves names, so only literal
    addresses can be checked."""
    if ctx.options.mode and any(m.startswith("upstream:") for m in ctx.options.mode):
        return None
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port)
    except OSError:
        await asyncio.sleep(0.5)  # the resolver may still be waking up
        try:
            infos = await loop.getaddrinfo(host, port)
        except OSError:
            return "unresolved"
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return "private"
        except ValueError:
            return "private"
    return None


async def why_unreachable(host, port, tunnel=False):
    """Return the reason a host outside the hosts file is out of reach, or None.
    A CONNECT tunnel is only for TLS on 443: plain HTTP goes as plain HTTP, so
    that the proxy sees it (and the upstream proxy's login never ends up in it)."""
    if is_private_name(host):
        return "private addresses are not reachable from the sandbox"
    if port not in ((443,) if tunnel else (80, 443)):
        return f"port {port} is not reachable from the sandbox" + (", only 443 for a tunnel" if tunnel else ", only 80 and 443")
    resolved = await resolves_private(host, port)
    if resolved == "unresolved":
        return "that name could not be resolved"
    if resolved == "private":
        return "that name points to a private address"
    return None


# ------------------------------------------------------------------ the proxy

class ReadOnly:
    def __init__(self):
        self.audit_window = 0
        self.audit_count = 0
        self.audit_dropped = 0
        self.audit_budget_window = 0
        self.audit_budget_used = 0

    async def http_connect(self, flow: http.HTTPFlow):
        # A CONNECT from the sandbox: an HTTPS (or other TLS) tunnel is asked for.
        host, port = flow.request.host.lower(), flow.request.port
        if host in TOKENS:
            return
        if host == AUDIT_HOST:
            self.block(flow, "events are posted as plain HTTP")
            return
        reason = await why_unreachable(host, port, tunnel=True)
        if reason:
            self.block(flow, reason)

    def tls_clienthello(self, data: tls.ClientHelloData):
        # Only open up connections to hosts from the hosts file. Everything else
        # stays encrypted end to end. We look at the host the sandbox asked to
        # connect to, not at the name it puts in the TLS handshake.
        host, port = data.context.server.address[0].lower(), data.context.server.address[1]
        if host not in TOKENS:
            data.ignore_connection = True
            note_passthrough(host, port)

    async def requestheaders(self, flow: http.HTTPFlow):
        # Everything is decided here, before a byte of the request goes out.
        request = flow.request
        host = request.host.lower()

        if host == AUDIT_HOST:
            if request.method != "POST":
                flow.response = http.Response.make(405)
            elif int(request.headers.get("Content-Length", "0") or 0) > AUDIT_MAX_BYTES:
                flow.response = http.Response.make(413)
            else:
                request.stream = False  # the body is read in request() below
            return

        if host not in TOKENS:
            # Plain HTTP to some other host. Passed through as it is.
            reason = await why_unreachable(host, request.port)
            if reason:
                self.block(flow, reason)
            else:
                note_passthrough(host, request.port, method=request.method, path=logged_path(request.path))
            return

        # A host with a token. Never let an error in here turn into a request
        # going out with, or without, the token.
        try:
            self.with_token(flow)
        except Exception as e:  # noqa: BLE001
            self.block(flow, f"proxy error: {e}")

    def with_token(self, flow):
        request = flow.request
        host = request.host.lower()
        kind, token = TOKENS[host]

        # The Host header must name the same host we connected to, otherwise the
        # token could end up at another server.
        header_host = request.host_header.split(":")[0].lower() if request.host_header else host
        if header_host != host:
            self.block(flow, "Host header does not match the connection")
            return

        reason = why_blocked(request, kind)
        if reason:
            self.block(flow, reason)
            return

        # Drop whatever credentials the sandbox sent and add ours.
        for name in ("Authorization", "PRIVATE-TOKEN", "Cookie", "Proxy-Authorization"):
            request.headers.pop(name, None)

        if request.path.split("?", 1)[0] == "/graphql":
            request.stream = False  # request() below looks at the body first
            flow.metadata["ssbx_graphql"] = True

        is_git = GIT_READ.match(request.path.split("?", 1)[0]) is not None
        request.headers.update(auth_headers(kind, token, is_git))

        if not flow.metadata.get("ssbx_graphql"):
            self.allowed(flow)

    def allowed(self, flow):
        request = flow.request
        log_event({"source": "proxy", "event": "allowed", "method": request.method,
                   "host": request.host.lower(), "path": logged_path(request.path)})

    def request(self, flow: http.HTTPFlow):
        if flow.response is not None:
            return
        if flow.request.host.lower() == AUDIT_HOST:
            self.audit(flow)
        elif flow.metadata.get("ssbx_graphql"):
            # A GraphQL document that writes has to say "mutation".
            body = flow.request.get_text(strict=False) or ""
            if GRAPHQL_MUTATION.search(body):
                flow.request.headers.pop("Authorization", None)
                self.block(flow, "a GraphQL mutation would change something, only reading is allowed")
            else:
                self.allowed(flow)

    def block(self, flow, reason):
        request = flow.request
        flow.response = http.Response.make(
            403,
            f"Blocked by the ssbx proxy: {reason}\n",
            {"Content-Type": "text/plain"},
        )
        log_event({"source": "proxy", "event": "blocked", "method": request.method,
                   "host": request.host.lower(), "path": logged_path(request.path), "reason": reason})

    def audit(self, flow):
        """An event reported by the sandbox itself. Logged, never forwarded.
        The sandbox cannot read or change the log; it can only add to it, and
        only so much per second."""
        body = flow.request.get_content(strict=False) or b""
        if len(body) > AUDIT_MAX_BYTES:
            flow.response = http.Response.make(413)
            return
        try:
            event = json.loads(body)
            if not isinstance(event, dict) or not isinstance(event.get("event"), str):
                raise ValueError("not an event")
        except ValueError:
            flow.response = http.Response.make(400)
            return

        second = int(time.monotonic())
        if second != self.audit_window:
            if self.audit_dropped:
                log_event({"source": "proxy", "event": "dropped", "count": self.audit_dropped,
                           "reason": "too many events from the sandbox"})
            self.audit_window, self.audit_count, self.audit_dropped = second, 0, 0
        self.audit_count += 1
        budget_window = second // AUDIT_BUDGET_SECONDS
        if budget_window != self.audit_budget_window:
            self.audit_budget_window, self.audit_budget_used = budget_window, 0
        self.audit_budget_used += len(body)
        if self.audit_count > AUDIT_MAX_PER_SECOND or self.audit_budget_used > AUDIT_BUDGET_BYTES:
            self.audit_dropped += 1
            flow.response = http.Response.make(429)
            return

        event.pop("ts", None)
        event["source"] = "sandbox"  # self-reported, whatever the sandbox claims
        log_event(event)
        flow.response = http.Response.make(204)


addons = [ReadOnly()]
