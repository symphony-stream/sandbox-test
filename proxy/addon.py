"""
The ssbx proxy. It runs on your machine; the VM can reach nothing else.

Everything the sandbox sends comes through here and is checked against the
allowlist in ssbx.toml (see rules.py for the format). Hosts that are not in
the list are refused. For hosts with a token the proxy adds the token to the
requests it lets through, so the token never enters the VM.

Three kinds of hosts:
  - tunnel:    `allow = "*"` and no token. The TLS connection is passed
               through as it is; the proxy sees only the host and port.
  - intercept: every other listed host. The proxy ends the TLS connection
               with its own certificate (the VM trusts it), looks at each
               request's method and path, and refuses what no entry allows.
  - token:     intercepted, plus the token is added.

Every decision is made when the request headers arrive, before a byte goes
out; only GraphQL documents are read first, to tell queries from mutations.
Decisions land in the audit log (SSBX_LOG_FILE), one JSON object per line.
Claude Code inside the VM reports its own events (tool calls, refusals) to
the same log by posting them to http://ssbx.audit/, a name that exists only
here. Those events carry "source": "sandbox"; the proxy's carry "source": "proxy".

Started by the ssbx launcher: mitmdump -s addon.py, with SSBX_CONFIG pointing
at ssbx.toml.
"""

import asyncio
import json
import os
import re
import socket
import sys
import time
import tomllib
from datetime import datetime, timezone

from mitmproxy import ctx, http, tls

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rules  # noqa: E402

CONFIG_FILE = os.environ.get("SSBX_CONFIG", "")
LOG_FILE = os.environ.get("SSBX_LOG_FILE", "")
LOG_MAX_BYTES = 20 * 1024 * 1024  # then the log is rotated once, to <name>.1

AUDIT_HOST = "ssbx.audit"  # where the sandbox posts its events; never forwarded
AUDIT_MAX_BYTES = 16 * 1024
AUDIT_MAX_PER_SECOND = 20
AUDIT_BUDGET_BYTES = 4 * 1024 * 1024  # per AUDIT_BUDGET_SECONDS, so a flood cannot push the proxy's own records out
AUDIT_BUDGET_SECONDS = 600

GRAPHQL_MAX_BYTES = 1024 * 1024
REPEAT_WINDOW = 60      # identical refusals within this many seconds become one event
SUMMARY_EVERY = 300     # GETs on intercepted hosts and tunnels are summarised this often

VALID_METHODS = set(rules.METHODS) | {"HEAD"}


def read_config():
    try:
        with open(CONFIG_FILE, "rb") as f:
            config = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        sys.exit(f"ssbx proxy: cannot read {CONFIG_FILE}: {e}")
    try:
        return rules.load(config.get("hosts"))
    except rules.ConfigError as e:
        sys.exit(f"ssbx proxy: {CONFIG_FILE}: {e}")


RULES = read_config()


# ------------------------------------------------------------------ the log

def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log_event(event):
    """Append one event to the audit log."""
    event = {"ts": now(), **event}
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace") + b"\n"
    if not LOG_FILE:
        sys.stdout.buffer.write(line)
        sys.stdout.flush()
        return
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
            os.replace(LOG_FILE, LOG_FILE + ".1")
        with open(LOG_FILE, "ab") as f:
            f.write(line)
    except Exception as e:  # noqa: BLE001
        print(f"ssbx proxy: cannot write {LOG_FILE}: {e}", file=sys.stderr, flush=True)


# Query strings can carry tokens (?private_token=...). Their values are not logged.
SECRET_PARAM = re.compile(r"(?i)([^&=]*(token|key|secret|pass|auth|sig)[^&=]*=)[^&]*")


def logged_path(path):
    if "?" not in path:
        return path
    path, query = path.split("?", 1)
    return path + "?" + SECRET_PARAM.sub(r"\1***", query)


# ------------------------------------------------------------------ addresses

def upstream_mode():
    return bool(ctx.options.mode) and any(str(m).startswith("upstream:") for m in ctx.options.mode)


async def resolve(host, port):
    """(address, None) for the address the proxy will connect to, or
    (None, reason). IPv4 first. With an upstream proxy the upstream resolves
    names, so nothing is checked here."""
    if upstream_mode():
        return None, None
    loop = asyncio.get_running_loop()
    infos = None
    for attempt in (1, 2):
        try:
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            break
        except OSError:
            if attempt == 1:
                await asyncio.sleep(0.5)  # the resolver may still be waking up
    if not infos:
        return None, f"{host} could not be resolved"
    addresses = [info[4][0] for info in infos]
    bad = [a for a in addresses if not rules.address_is_reachable(a)]
    if bad:
        return None, f"{host} points at {bad[0]}, which is not reachable from the sandbox"
    addresses.sort(key=lambda a: ":" in a)  # IPv4 first
    return addresses[0], None


# ------------------------------------------------------------------ the proxy

class Allowlist:
    def __init__(self):
        self.pinned = {}          # client connection id -> {(host, port): address}
        self.recent_blocks = {}   # (method, host, path, reason) -> [last logged, suppressed]
        self.get_counts = {}      # host -> [count, first seen]
        self.tunnel_counts = {}   # (host, port) -> [count, first seen]
        self.audit_window = 0
        self.audit_count = 0
        self.audit_dropped = 0
        self.audit_budget_window = 0
        self.audit_budget_used = 0

    def running(self):
        if ctx.options.connection_strategy != "lazy":
            print("ssbx proxy: connection_strategy should be lazy", file=sys.stderr, flush=True)
        modes = {"tunnel": [], "intercept": [], "token": []}
        for host in RULES.hosts():
            modes[host.mode].append(host.name)
        warnings = RULES.warnings()
        if upstream_mode():
            warnings.append("an upstream proxy resolves names, so addresses are not checked here")
        for w in warnings:
            print(f"ssbx proxy: {w}", file=sys.stderr, flush=True)
        log_event({"source": "proxy", "event": "rules", **modes, "warnings": warnings})
        print(f"ssbx proxy: {len(modes['tunnel'])} tunnel, {len(modes['intercept'])} intercepted, "
              f"{len(modes['token'])} with token", file=sys.stderr, flush=True)

    def done(self):
        self.flush_summaries(force=True)

    # -- connections ------------------------------------------------------

    async def http_connect(self, flow: http.HTTPFlow):
        """A CONNECT from the sandbox: it wants a TLS tunnel to host:port."""
        host, port = rules.normalize_host(flow.request.host), flow.request.port
        if host == AUDIT_HOST:
            self.block(flow, "events are posted as plain HTTP")
            return
        if port != 443:
            self.block(flow, f"port {port} is not reachable, only 443 for HTTPS")
            return
        entry = RULES.find(host)
        if entry is None:
            return  # the tunnel is opened with our certificate, so the first request is logged with its path
        address, reason = await resolve(host, port)
        if reason:
            self.block(flow, reason)
            return
        if address:
            self.pinned.setdefault(flow.client_conn.id, {})[(host, port)] = address

    def tls_clienthello(self, data: tls.ClientHelloData):
        if not data.context.server.address:
            return
        host, port = data.context.server.address
        host = rules.normalize_host(host)
        entry = RULES.find(host)
        if entry is not None and entry.tunnel:
            data.ignore_connection = True  # end to end encrypted, we only see host and port
            self.count(self.tunnel_counts, (host, port), "passthrough", host=host, port=port)

    def server_connect(self, data):
        """Connect to the address that was checked, not to a second lookup."""
        host, port = data.server.address
        address = self.pinned.get(data.client.id, {}).get((rules.normalize_host(host), port))
        if address:
            data.server.address = (address, port)

    def client_disconnected(self, client):
        self.pinned.pop(client.id, None)

    # -- requests ---------------------------------------------------------

    async def requestheaders(self, flow: http.HTTPFlow):
        """Everything is decided here, before the request goes anywhere."""
        request = flow.request
        host = rules.normalize_host(request.host)

        if host == AUDIT_HOST:
            if request.scheme != "http" or request.method != "POST":
                flow.response = http.Response.make(405)
            elif int(request.headers.get("Content-Length", "0") or 0) > AUDIT_MAX_BYTES:
                flow.response = http.Response.make(413)
            else:
                request.stream = False  # the body is read in request() below
            return

        try:
            await self.check(flow, host)
        except Exception as e:  # noqa: BLE001
            self.block(flow, f"proxy error: {e}")  # an error never lets a request out

    async def check(self, flow, host):
        request = flow.request
        entry = RULES.find(host)
        plain = request.scheme == "http"

        if plain and request.port != 80:
            self.block(flow, f"port {request.port} is not reachable, only 80 for plain HTTP")
            return
        if entry is None:
            self.block(flow, RULES.decide(host, request.method, request.path))
            return
        if plain and entry.token is not None:
            self.block(flow, "a host with a token is only reachable over HTTPS")
            return

        # The request has to be about the host the connection was opened to.
        header_host = request.host_header or host
        if header_host.startswith("["):
            header_host = header_host[1:].split("]", 1)[0]
        elif header_host.count(":") == 1:
            header_host = header_host.rsplit(":", 1)[0]
        if rules.normalize_host(header_host) != host:
            self.block(flow, "the Host header names another host")
            return

        method = request.method
        if method not in VALID_METHODS:
            self.block(flow, f"unusual method {method!r}")
            return
        if "upgrade" in request.headers.get("Connection", "").lower() or "Upgrade" in request.headers:
            self.block(flow, "WebSockets and other upgrades are not allowed")
            return
        if "X-HTTP-Method-Override" in request.headers or "X-Method-Override" in request.headers \
                or "_method=" in request.path.split("?", 1)[-1]:
            self.block(flow, "a method override is not allowed")
            return
        length = request.headers.get("Content-Length")
        if length is not None and not length.strip().isdigit():
            self.block(flow, "bad Content-Length")
            return

        path = request.path
        reason = rules.why_unusual_path(path)
        if reason:
            self.block(flow, reason)
            return
        if entry.token is not None and rules.hands_out_credentials(path):
            self.block(flow, "that endpoint hands out credentials")
            return

        if plain:  # the address is checked here, a CONNECT never happened
            address, reason = await resolve(host, 80)
            if reason:
                self.block(flow, reason)
                return
            if address:
                self.pinned.setdefault(flow.client_conn.id, {})[(host, 80)] = address

        # Whatever credentials the sandbox sent, they do not go to a host with a token.
        if entry.token is not None:
            for name in ("Authorization", "PRIVATE-TOKEN", "Cookie", "Proxy-Authorization"):
                request.headers.pop(name, None)

        git = rules.git_request(method, path, request.headers.get("Content-Type", ""))
        if git is not None:
            decision = RULES.decide(host, method, git[1], git=git[0])
            self.settle(flow, entry, decision, is_git=True)
            return

        if rules.is_graphql_path(path):
            if method != "POST":
                self.block(flow, "GraphQL is only allowed as POST")
                return
            length = request.headers.get("Content-Length", "")
            if not length.isdigit() or int(length) > GRAPHQL_MAX_BYTES:
                self.block(flow, "a GraphQL request needs a Content-Length of at most 1 MB")
                return
            request.stream = False  # request() reads the document and decides
            flow.metadata["ssbx_graphql"] = entry
            return

        self.settle(flow, entry, RULES.decide(host, method, path))

    def request(self, flow: http.HTTPFlow):
        if flow.response is not None:
            return
        host = rules.normalize_host(flow.request.host)
        if host == AUDIT_HOST:
            self.audit(flow)
            return
        entry = flow.metadata.get("ssbx_graphql")
        if entry is None:
            return
        try:
            body = flow.request.get_content(strict=False) or b""
            operations = rules.graphql_operations(body, GRAPHQL_MAX_BYTES)
        except ValueError as e:
            self.block(flow, f"not a readable GraphQL request ({e})")
            return
        except Exception as e:  # noqa: BLE001
            self.block(flow, f"proxy error: {e}")
            return
        self.settle(flow, entry, RULES.decide(host, flow.request.method, flow.request.path, graphql=operations))

    def settle(self, flow, entry, decision, is_git=False):
        if not decision.allowed:
            self.block(flow, decision)
            return
        request = flow.request
        if entry.token is not None:
            request.headers.update(rules.auth_headers(entry.kind, entry.token, is_git))
        host = rules.normalize_host(request.host)
        if entry.token is None and request.method in ("GET", "HEAD"):
            self.count(self.get_counts, host, "allowed", host=host, method="GET")
            return
        log_event({"source": "proxy", "event": "allowed", "method": request.method, "host": host,
                   "path": logged_path(request.path), "rule": decision.rule})

    def block(self, flow, why):
        """Answer 403 and log it. why is a reason string or a Decision."""
        request = flow.request
        reason = why if isinstance(why, str) else why.reason
        suggest = None if isinstance(why, str) else why.suggest
        flow.response = http.Response.make(
            403, f"Blocked by the ssbx proxy: {reason}\n" + (f"\nTo allow it, add to ssbx.toml:\n{suggest}\n" if suggest else ""),
            {"Content-Type": "text/plain"})
        method = request.method
        path = "" if method == "CONNECT" else logged_path(request.path)
        key = (method, rules.normalize_host(request.host), path, reason)
        clock = time.monotonic()
        recent = self.recent_blocks.get(key)
        if recent and clock - recent[0] < REPEAT_WINDOW:
            recent[1] += 1
            return
        event = {"source": "proxy", "event": "blocked", "method": method, "host": key[1], "path": path, "reason": reason}
        if request.method == "CONNECT":
            event["port"] = request.port
        if suggest:
            event["suggest"] = suggest
        if recent and recent[1]:
            event["repeated"] = recent[1]
        log_event(event)
        self.recent_blocks[key] = [clock, 0]
        if len(self.recent_blocks) > 1000:
            self.recent_blocks = {k: v for k, v in self.recent_blocks.items() if clock - v[0] < REPEAT_WINDOW}

    # -- summaries --------------------------------------------------------

    def count(self, table, key, event, **fields):
        """Log the first occurrence at once, then one summary per SUMMARY_EVERY."""
        clock = time.monotonic()
        entry = table.get(key)
        if entry is None:
            log_event({"source": "proxy", "event": event, **fields})
            table[key] = [0, clock, fields]
            return
        entry[0] += 1
        if clock - entry[1] >= SUMMARY_EVERY:
            log_event({"source": "proxy", "event": event, **entry[2], "count": entry[0]})
            table[key] = [0, clock, fields]

    def flush_summaries(self, force=False):
        for table in (self.get_counts, self.tunnel_counts):
            for key, entry in list(table.items()):
                if entry[0] and (force or time.monotonic() - entry[1] >= SUMMARY_EVERY):
                    log_event({"source": "proxy", "event": "allowed" if table is self.get_counts else "passthrough",
                               **entry[2], "count": entry[0]})
                    del table[key]

    # -- the sandbox's own events -----------------------------------------

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


addons = [Allowlist()]
