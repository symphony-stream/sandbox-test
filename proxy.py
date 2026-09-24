"""
ssbx proxy: the sandbox's only way out. Runs inside the VM as `mitmdump -s
proxy.py --set ssbx_config=~/.config/ssbx/ssbx.toml`, reloaded every 3 s.

ssbx.toml:
  proxy = "http://user:pass@host:port"   # optional upstream, for all traffic
  log = "blocked"                        # or "all"; refusals always log
  [hosts."name"]                         # exact host, or "*.name"
  allow = "METHODS [PATH]"               # GET/POST/PUT/PATCH/DELETE/OPTIONS/
                                          # git-fetch/git-push/graphql/*, path:
                                          # * one segment, ** any, none = all
  kind = "github"; token = "..."         # gitlab/github/atlassian/bearer
  mutations = ["addComment"]             # allowed GraphQL mutation names

`allow = "*"` with no token tunnels the connection (CONNECT host and TLS SNI
checked, then passed through end to end encrypted); everything else is
intercepted with this proxy's own certificate. Events go to proxy.log next
to ssbx.toml, one JSON line each: blocked (always), allowed (log="all"),
config_error, reload.
"""
from __future__ import annotations
import asyncio
import base64
import ipaddress
import json
import re
import socket
import sys
import tomllib
import urllib.parse
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path
try:  # everything below "addon" has no mitmproxy dependency, and is unit-tested without it
    from mitmproxy import ctx, http, tls
except ImportError:
    ctx = http = tls = None

LOG_MAX_BYTES = 20 * 1024 * 1024  # then the log is rotated once, to <name>.1
GRAPHQL_MAX_BYTES = 1024 * 1024
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
SPECIAL = ("git-fetch", "git-push", "graphql", "*")
KINDS = ("gitlab", "github", "atlassian", "bearer")
# Names that are never a valid host for the sandbox, whatever the file says.
RESERVED_NAMES = {"localhost", "host.lima.internal", "host.docker.internal"}
RESERVED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".arpa", ".onion")
LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
ID_LIKE = re.compile(r"^(\d{2,}|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{32,36})$")
GRAPHQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")

class ConfigError(Exception):
    pass  # something in the [hosts] tables is wrong; the message says what

Decision = namedtuple("Decision", "allowed reason rule suggest", defaults=("", None, None))

# ------------------------------------------------------------------ hosts
def is_ip_literal(name):  # 10.0.0.1, 127.1, 0x7f000001, ::1, ... - any IP spelling, not a name
    bare = name.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        pass
    if ":" in bare:
        return True  # looks like IPv6 and did not parse: still not a name
    labels = [label for label in bare.split(".") if label]
    return bool(labels) and all(re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", label) for label in labels)

def normalize_host(name):  # lowercase, no trailing dot, punycode for non-ASCII names
    name = name.strip().rstrip(".").lower()
    try:
        name.encode("ascii")
        return name
    except UnicodeEncodeError:
        return name.encode("idna").decode("ascii")

def check_host_name(name, where):
    if name.startswith("*."):
        rest = name[2:]
        if rest.count(".") < 1 or "*" in rest:
            raise ConfigError(f'{where}: a wildcard needs "*." followed by an exact name of two labels or more')
        name = rest
    if "*" in name or "." not in name or is_ip_literal(name) or name in RESERVED_NAMES or name.endswith(RESERVED_SUFFIXES) or not all(LABEL.match(label) for label in name.split(".")):
        raise ConfigError(f"{where}: {name!r} is not a host the sandbox can reach")

def address_is_reachable(address):
    # False for loopback/link-local/unspecified/multicast/reserved, and for
    # 192.168.5.0/24 - the Lima host subnet, where host.lima.internal (the
    # user's own machine) lives.
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return False
    return not (ip.version == 4 and ip in ipaddress.ip_network("192.168.5.0/24"))

# ------------------------------------------------------------------ paths
def why_unusual_path(path):
    # Refused before matching, which happens on the fully percent-decoded path (normalize_path): a literal
    # or decoded control character, backslash, doubled slash, or "." / ".." segment, and a doubly-encoded
    # percent sign (which would decode again downstream).
    path = path.split("?", 1)[0]
    if not path.startswith("/"):
        return "the path does not start with /"
    if "%25" in path:
        return "the path percent-encodes a percent sign, which would double-decode"
    try:
        decoded = urllib.parse.unquote(path, errors="strict")
    except UnicodeDecodeError:
        return "the path percent-encodes bytes that are not valid UTF-8"
    if any(ord(c) < 32 or ord(c) == 127 for c in decoded) or "\\" in decoded or "//" in decoded or any(segment in (".", "..") for segment in decoded.split("/")):
        return "the path contains, or percent-decodes to, control characters, a backslash, //, or . / .."
    return None

def normalize_path(path):  # the decoded path used for matching and logging; call why_unusual_path first
    path = path.split("?", 1)[0] or "/"
    try:
        path = urllib.parse.unquote(path, errors="strict")
    except UnicodeDecodeError:
        pass
    return path[:-1] if len(path) > 1 and path.endswith("/") else (path or "/")

def compile_path(pattern, where):  # a rule path into a regex over decoded segments: "*" one, "**" any number
    if not pattern.startswith("/") or any(c in pattern for c in "?# \t\\") or "//" in pattern:
        raise ConfigError(f"{where}: the path must start with / and not contain spaces, ?, #, \\ or //")
    parts = []
    for segment in pattern.split("/")[1:]:
        if segment == "**":
            parts.append("(?:/[^/]+)*")
        elif "**" in segment or segment in (".", ".."):
            raise ConfigError(f"{where}: ** has to be a whole segment, and . or .. are not allowed")
        elif segment == "*":
            parts.append("/[^/]+")
        else:
            parts.append("/" + "[^/]*".join(re.escape(piece) for piece in segment.split("*")))
    body = "".join(parts)
    return re.compile("^" + (f"(?:/|{body})" if re.fullmatch(body, "") else body) + "$")

# ------------------------------------------------------------------ rules
Rule = namedtuple("Rule", "text methods path regex")  # methods: a set of tokens; regex: compiled or None

def rule_allows(rule, method, path):  # method is a request method, or git-fetch/git-push/graphql
    matches = rule.regex is None or rule.regex.match(normalize_path(path)) is not None
    return matches and ("*" in rule.methods or (method if method != "HEAD" else "GET") in rule.methods)

def parse_rule(text, where):
    if not isinstance(text, str) or not text.strip():
        raise ConfigError(f"{where}: every allow entry is a string like \"GET\" or \"POST /path\"")
    parts = text.split()
    if len(parts) > 2:
        raise ConfigError(f"{where}: {text!r} has more than a method list and a path; one entry per rule")
    methods = set()
    for token in parts[0].split(","):
        token, upper = token.strip(), token.strip().upper()
        if upper in METHODS or upper == "HEAD":
            methods.add("GET" if upper == "HEAD" else upper)
        elif token.lower() in SPECIAL:
            methods.add(token.lower())
        else:
            raise ConfigError(f"{where}: unknown method {token!r} in {text!r} (GET POST PUT PATCH DELETE OPTIONS git-fetch git-push graphql or *)")
    path = parts[1] if len(parts) == 2 else None
    return Rule(text, methods, path, compile_path(path, f"{where}: {text!r}") if path else None)

class Host:
    def __init__(self, name, where):
        self.name, self.where = name, where
        self.wildcard = name.startswith("*.")
        self.kind = self.token = None
        self.mutations = set()
        self.rules = []

    @property
    def tunnel(self):  # no token, and "*" on every path: the proxy does not look inside
        return self.token is None and any("*" in r.methods and r.path is None for r in self.rules)

    @property
    def mode(self):
        return "token" if self.token is not None else ("tunnel" if self.tunnel else "intercept")

    def allowing(self, method, path):
        return next((r for r in self.rules if rule_allows(r, method, path)), None)

def load_rules(hosts_table):  # the [hosts] tables (a dict, as tomllib gives it) into a Rules object
    hosts_table = hosts_table or {}
    if not isinstance(hosts_table, dict):
        raise ConfigError("[hosts] must be a table")
    exact, wildcards = {}, []
    for raw_name, table in hosts_table.items():
        where = f'[hosts."{raw_name}"]'
        if not isinstance(table, dict):
            raise ConfigError(f"{where} must be a table with allow = ...")
        name = normalize_host(raw_name)
        check_host_name(name, where)
        host = Host(name, where)
        unknown = set(table) - {"allow", "kind", "token", "mutations"}
        if unknown:
            raise ConfigError(f"{where}: unknown keys {sorted(unknown)} (allow, kind, token, mutations)")
        allow = table.get("allow", [])
        allow = [allow] if isinstance(allow, str) else allow
        if not isinstance(allow, list):
            raise ConfigError(f"{where}: allow must be a string or a list of strings")
        host.rules = [parse_rule(text, where) for text in allow]
        kind, token = table.get("kind"), table.get("token")
        if (kind is None) != (token is None):
            raise ConfigError(f"{where}: kind and token go together")
        if kind is not None:
            if kind not in KINDS or not isinstance(token, str) or not token.strip() or host.wildcard or (kind == "atlassian" and ":" not in token):
                raise ConfigError(f"{where}: kind must be one of {', '.join(KINDS)}, with a non-empty token (atlassian: email:api-token), and an exact host, not a wildcard")
            host.kind, host.token = kind, token.strip()
            auth_headers(kind, host.token, False)  # a bad token shape fails here, not on first use
        mutations = table.get("mutations", [])
        mutations = [mutations] if isinstance(mutations, str) else mutations
        if not isinstance(mutations, list) or not all(isinstance(m, str) and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z*]*", m.strip()) for m in mutations):
            raise ConfigError(f"{where}: mutations must be a list of GraphQL mutation names")
        host.mutations = {m.strip() for m in mutations}
        if host.wildcard:
            wildcards.append(host)
        elif name in exact:
            raise ConfigError(f"{where} is listed twice")
        else:
            exact[name] = host
    wildcards.sort(key=lambda h: -len(h.name))  # the most specific wildcard first
    return Rules(exact, wildcards)

class Rules:
    def __init__(self, exact, wildcards):
        self.exact, self.wildcards = exact, wildcards

    def hosts(self):
        return list(self.exact.values()) + self.wildcards

    def find(self, host):
        host = normalize_host(host)
        if host in self.exact:
            return self.exact[host]
        return next((e for e in self.wildcards if host.endswith(e.name[1:]) and host != e.name[2:]), None)

    def decide(self, host, method, path, git=None, graphql=None):
        # git: None, "fetch" or "push" for git smart HTTP (path is then the repo path). graphql: None, or
        # the operations of a document, as graphql_operations() returns them.
        entry = self.find(host)
        if entry is None:
            name = normalize_host(host)
            if is_ip_literal(name) or name in RESERVED_NAMES or name.endswith(RESERVED_SUFFIXES) or "." not in name:
                return Decision(False, f"{name} is an address or a local name, never reachable from the sandbox")
            return Decision(False, f"{name} is not in your allowlist", suggest=suggest(host, method, path, git, graphql))
        if git is not None:
            wanted = "git-fetch" if git == "fetch" else "git-push"
            rule = entry.allowing(wanted, path)
            if rule is None:
                return Decision(False, f"git {git} to {path} is not allowed on {entry.name}", suggest=suggest(host, method, path, git, graphql))
            return Decision(True, f"{wanted} {path}", rule=rule.text)
        if graphql is not None:
            return decide_graphql(entry, host, method, path, graphql)
        rule = entry.allowing(method, path)
        if rule is None:
            return Decision(False, f"{method} {normalize_path(path)} is not allowed on {entry.name}", suggest=suggest(host, method, path, git, graphql))
        return Decision(True, f"{method} {normalize_path(path)}", rule=rule.text)

def decide_graphql(entry, host, method, path, graphql):
    if method != "POST":
        return Decision(False, "GraphQL is only allowed as POST")
    rule = entry.allowing("graphql", path)
    if rule is None:
        return Decision(False, f"GraphQL on {path} is not allowed on {entry.name}", suggest=suggest(host, method, path, None, graphql))
    if not graphql:
        return Decision(False, "the GraphQL document has no operation to look at")
    # mutations, once configured, are checked whatever rule matched: a bare "*" entry must not skip the
    # gate just because it matched too.
    if entry.mutations or "*" not in rule.methods:
        for kind, names in graphql:
            if kind == "query":
                continue
            if kind != "mutation":
                return Decision(False, "the GraphQL document could not be read, so it is refused" if kind == "unknown" else f"GraphQL {kind}s are not allowed")
            refused = [n for n in names if not mutation_allowed(entry, n)]
            if not names or refused:
                return Decision(False, "GraphQL mutation " + ", ".join(refused or ["?"]) + f" is not allowed on {entry.name}", suggest=suggest(host, method, path, None, graphql))
    return Decision(True, f"graphql {path}", rule=rule.text)

def mutation_allowed(entry, name):
    return any(pattern == name or ("*" in pattern and re.fullmatch(".*".join(re.escape(p) for p in pattern.split("*")), name)) for pattern in entry.mutations)

def suggest(host, method, path, git=None, graphql=None):  # a ready-to-paste TOML snippet that would allow this request
    host = normalize_host(host)
    if git is not None:
        line = f'allow = "{"git-fetch" if git == "fetch" else "git-push"} {path}"'
    elif graphql is not None:
        names = sorted({n for kind, ns in graphql for n in ns if kind == "mutation"})
        line = f'allow = "graphql {normalize_path(path)}"' + (f'\nmutations = {json.dumps(names)}' if names else "")
    else:
        method = "GET" if method == "HEAD" else method
        segments = normalize_path(path).split("/")[1:]
        generic = "/" + "/".join("*" if ID_LIKE.match(s) else s for s in segments)
        line = f'allow = "{method}"' if method == "GET" else f'allow = "{method} {generic}"'
    return f'[hosts."{host}"]\n{line}'

# ------------------------------------------------------------------ git
GIT_END = re.compile(r"^(?P<repo>/.+?)(?:\.git)?/(?P<what>info/refs|git-upload-pack|git-receive-pack)$")

def git_request(method, path_with_query, content_type=""):  # (kind, repo) for git smart HTTP, else None
    path, _, query = path_with_query.partition("?")
    path = normalize_path(path)  # decoded once, so a %2F namespace separator is a real one here too
    if path.startswith("/api/"):
        return None  # an API path takes its last segment for a file name, not this
    m = GIT_END.match(path)
    if not m:
        return None
    what, repo = m.group("what"), m.group("repo")
    if what == "info/refs":
        if method != "GET":
            return None
        service = dict(p.split("=", 1) for p in query.split("&") if "=" in p).get("service", "")
        return ("fetch", repo) if service == "git-upload-pack" else ("push", repo) if service == "git-receive-pack" else None
    if method != "POST" or not content_type.lower().startswith(f"application/x-{what}-request"):
        return None
    return ("fetch" if what == "git-upload-pack" else "push"), repo

# ------------------------------------------------------------------ graphql
def is_graphql_path(path):
    return normalize_path(path).rsplit("/", 1)[-1].lower() == "graphql"

def graphql_operations(body, limit=1024 * 1024):
    # [(kind, [top-level field names])], kind being query, mutation, subscription, or unknown when the
    # document could not be read.
    if len(body) > limit:
        raise ValueError("body too big")
    document = json.loads(body)
    items = document if isinstance(document, list) else [document]
    if not items:
        raise ValueError("empty batch")
    operations = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("query"), str):
            raise ValueError("no query text")
        operations.extend(parse_document(item["query"]))
    return operations

TOKEN = re.compile(r"[_A-Za-z][_0-9A-Za-z]*|\.\.\.|[{}()]")

def parse_document(text):
    # A light, token-level reading: a directive is skipped over rather than understood (can add a harmless
    # spurious name, never hides a real one); a fragment spread makes the whole document ("unknown", []),
    # which the caller refuses - always conservative, never a false allow.
    text = re.sub(r'"""(?:.|\n)*?"""|"(?:\\.|[^"\\\n])*"', '""', text)
    tokens = TOKEN.findall(re.sub(r"#[^\n]*", "", text))
    ops, i, n = [], 0, len(tokens)
    while i < n:
        keyword = tokens[i] if tokens[i] in ("query", "mutation", "subscription") else None
        if keyword:
            i += 1
            if i < n and tokens[i] not in ("{", "("):
                i += 1  # the operation's own name
        if i < n and tokens[i] == "(":
            i = skip_block(tokens, i, "(", ")")
        if i >= n or tokens[i] != "{":
            return [("unknown", [])]
        names, i = top_level_fields(tokens, i)
        if names is None:
            return [("unknown", [])]
        ops.append((keyword or "query", names))
    return ops or [("unknown", [])]

def skip_block(tokens, i, open_, close):  # from an opening bracket token at i to past its matching close
    depth, n = 0, len(tokens)
    while i < n:
        if tokens[i] == open_:
            depth += 1
        elif tokens[i] == close:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n

def top_level_fields(tokens, i):  # (names, index after) for tokens[i]=="{"; (None, ...) for a fragment spread
    i += 1
    names, n = [], len(tokens)
    while i < n and tokens[i] != "}":
        if tokens[i] == "..." or not GRAPHQL_NAME.fullmatch(tokens[i]):
            return None, i
        name, i = tokens[i], i + 1
        if i < n and tokens[i] == ":":  # alias: the real field name follows
            i += 1
            if i >= n or not GRAPHQL_NAME.fullmatch(tokens[i]):
                return None, i
            name, i = tokens[i], i + 1
        names.append(name)
        if i < n and tokens[i] == "(":
            i = skip_block(tokens, i, "(", ")")
        if i < n and tokens[i] == "{":
            i = skip_block(tokens, i, "{", "}")
    return (names, i + 1) if i < n else (None, i)

# ------------------------------------------------------------------ tokens
def basic_auth(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

def auth_headers(kind, token, is_git):  # the header that carries the token, as each service expects it
    if kind == "gitlab":
        return {"Authorization": basic_auth("oauth2", token)} if is_git else {"PRIVATE-TOKEN": token}
    if kind == "github":
        return {"Authorization": basic_auth("x-access-token", token)} if is_git else {"Authorization": f"Bearer {token}"}
    if kind == "atlassian":
        email, api_token = token.split(":", 1)
        return {"Authorization": basic_auth(email, api_token)}
    if kind == "bearer":
        return {"Authorization": f"Bearer {token}"}
    raise ConfigError(f"unknown kind {kind!r}")

# ==================================================================== addon
def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def upstream_mode():
    return bool(ctx.options.mode) and any(str(m).startswith("upstream:") for m in ctx.options.mode)

async def resolve(host, port):
    # None, or the reason the proxy will not connect to host:port. With an upstream proxy the upstream
    # resolves names, so nothing is checked here. No DNS pinning: mitmproxy resolves again, itself, when
    # it connects.
    if upstream_mode():
        return None
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return f"{host} could not be resolved"
    bad = [info[4][0] for info in infos if not address_is_reachable(info[4][0])]
    return f"{host} points at {bad[0]}, which is not reachable from the sandbox" if bad else None

class Allowlist:
    def __init__(self):
        self.authority = {}    # client connection id -> (host, port) from the CONNECT
        self.rules = load_rules(None)
        self.log_mode = "blocked"
        self.config_path = self.log_path = None
        self.checked = None    # mtime of ssbx.toml at the last load attempt

    def load(self, loader):
        loader.add_option(name="ssbx_config", typespec=str, default="", help="path to ssbx.toml")

    def running(self):
        if ctx.options.ssbx_config:
            self.config_path = Path(ctx.options.ssbx_config)
            self.log_path = self.config_path.parent / "proxy.log"
            self.reload()
            asyncio.get_running_loop().create_task(self.reload_loop())
        print(f"ssbx proxy: {len(self.rules.hosts())} hosts allowed", file=sys.stderr, flush=True)

    async def reload_loop(self):
        while True:
            await asyncio.sleep(3)
            self.reload()

    def reload(self):  # a broken or missing ssbx.toml keeps the last good rules
        try:
            mtime = self.config_path.stat().st_mtime
        except OSError as e:
            mtime, error = -1.0, str(e)
        else:
            error = None
        if mtime == self.checked:
            return
        self.checked = mtime
        if error is None:
            try:
                with open(self.config_path, "rb") as f:
                    config = tomllib.load(f)
                log_mode = config.get("log", "blocked")
                if log_mode not in ("all", "blocked"):
                    raise ConfigError('log must be "all" or "blocked"')
                rules = load_rules(config.get("hosts"))
            except (OSError, tomllib.TOMLDecodeError, ConfigError) as e:
                error = str(e)
            else:
                self.rules, self.log_mode = rules, log_mode
                self.log({"event": "reload", "hosts": len(rules.hosts())})
                return
        self.log({"event": "config_error", "error": error})

    def log(self, event):  # one JSON line appended to proxy.log, rotated once past 20 MB
        line = json.dumps({"ts": now(), **event}, ensure_ascii=False, separators=(",", ":"))
        if not self.log_path:
            print(line, flush=True)
            return
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > LOG_MAX_BYTES:
                self.log_path.replace(self.log_path.with_name(self.log_path.name + ".1"))
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            print(f"ssbx proxy: cannot write {self.log_path}: {e}", file=sys.stderr, flush=True)

    async def http_connect(self, flow: http.HTTPFlow):  # a CONNECT: the sandbox wants a TLS tunnel to host:port
        host, port = normalize_host(flow.request.host), flow.request.port
        if port != 443:
            return self.block(flow, f"port {port} is not reachable, only 443 for HTTPS")
        entry = self.rules.find(host)
        if entry is None:
            return self.block(flow, self.rules.decide(host, "GET", "/"))
        reason = await resolve(host, port)
        if reason:
            return self.block(flow, reason)
        self.authority[flow.client_conn.id] = (host, port)

    def tls_clienthello(self, data: tls.ClientHelloData):
        # A tunnel host is passed through untouched once its CONNECT host and TLS SNI agree; anything else
        # falls through to interception, where the request is checked against the CONNECT authority below.
        if not data.context.server.address:
            return
        host = normalize_host(data.context.server.address[0])
        entry = self.rules.find(host)
        if entry is not None and entry.tunnel and normalize_host(data.client_hello.sni or "") == host:
            data.ignore_connection = True

    def client_disconnected(self, client):
        self.authority.pop(client.id, None)

    async def requestheaders(self, flow: http.HTTPFlow):  # everything is decided here, before anything goes out
        try:
            await self.check(flow)
        except Exception as e:  # noqa: BLE001 - an error never lets a request out
            self.block(flow, f"proxy error: {e}")

    async def check(self, flow):
        request = flow.request
        host = normalize_host(request.host)
        plain = request.scheme == "http"
        # The one hard rule: for an intercepted flow, the request has to be about the host the CONNECT was
        # actually opened to; mitmproxy fills request.host from the Host header, which the sandbox controls.
        # request.port reflects the real connection, not a port the header claims, so that is checked too.
        header_port = (request.host_header or "").rsplit(":", 1)
        header_port = int(header_port[1]) if len(header_port) == 2 and header_port[1].isdigit() else request.port
        if not plain and (self.authority.get(flow.client_conn.id) != (host, request.port) or header_port != request.port):
            return self.block(flow, "the request does not match the connection's destination")
        if plain and request.port != 80:
            return self.block(flow, f"port {request.port} is not reachable, only 80 for plain HTTP")
        entry = self.rules.find(host)
        if entry is None:
            return self.block(flow, self.rules.decide(host, request.method, request.path))
        if plain and entry.token is not None:
            return self.block(flow, "a host with a token is only reachable over HTTPS")
        reason = why_unusual_path(request.path)
        if reason:
            return self.block(flow, reason)
        if plain:  # the address is checked here, a CONNECT never happened
            reason = await resolve(host, 80)
            if reason:
                return self.block(flow, reason)
        if entry.token is not None:  # whatever the sandbox sent, it is not forwarded
            for name in ("Authorization", "PRIVATE-TOKEN", "Cookie", "Proxy-Authorization"):
                request.headers.pop(name, None)
        method, path = request.method, request.path
        git = git_request(method, path, request.headers.get("Content-Type", ""))
        if git is not None:
            return self.settle(flow, entry, self.rules.decide(host, method, git[1], git=git[0]), is_git=True)
        if is_graphql_path(path):
            if method != "POST":
                return self.block(flow, "GraphQL is only allowed as POST")
            length = request.headers.get("Content-Length", "")
            if not length.isdigit() or int(length) > GRAPHQL_MAX_BYTES:
                return self.block(flow, "a GraphQL request needs a Content-Length of at most 1 MB")
            request.stream = False  # request() below reads the document and decides
            flow.metadata["ssbx_graphql"] = entry
            return
        self.settle(flow, entry, self.rules.decide(host, method, path))

    def request(self, flow: http.HTTPFlow):
        if flow.response is not None:
            return
        entry = flow.metadata.get("ssbx_graphql")
        if entry is None:
            return
        try:
            body = flow.request.get_content(strict=False) or b""
            operations = graphql_operations(body, GRAPHQL_MAX_BYTES)
        except ValueError as e:
            return self.block(flow, f"not a readable GraphQL request ({e})")
        host = normalize_host(flow.request.host)
        self.settle(flow, entry, self.rules.decide(host, flow.request.method, flow.request.path, graphql=operations))

    def settle(self, flow, entry, decision, is_git=False):
        if not decision.allowed:
            return self.block(flow, decision)
        request = flow.request
        if entry.token is not None:
            request.headers.update(auth_headers(entry.kind, entry.token, is_git))
        if self.log_mode == "all":
            self.log({"event": "allowed", "method": request.method, "host": normalize_host(request.host), "path": normalize_path(request.path)})

    def block(self, flow, why):  # answer 403 and log it; why is a reason string or a Decision
        request = flow.request
        reason = why if isinstance(why, str) else why.reason
        suggestion = None if isinstance(why, str) else why.suggest
        flow.response = http.Response.make(403, f"Blocked by the ssbx proxy: {reason}\n" + (f"\nTo allow it, add to ssbx.toml:\n{suggestion}\n" if suggestion else ""), {"Content-Type": "text/plain"})
        path = "" if request.method == "CONNECT" else normalize_path(request.path)
        host = normalize_host(request.host)
        event = {"event": "blocked", "method": request.method, "host": host, "path": path, "reason": reason}
        if suggestion:
            event["suggest"] = suggestion
        self.log(event)
        print(f"ssbx proxy: blocked {request.method} {host}{path}  ({reason})", file=sys.stderr, flush=True)

addons = [Allowlist()]
