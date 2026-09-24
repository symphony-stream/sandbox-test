"""
The ssbx allowlist: which hosts the sandbox may talk to, and what it may do
there. Everything not in the list is refused.

The list comes from the [hosts] tables in ssbx.toml:

    [hosts."example.atlassian.net"]
    kind = "atlassian"                      # optional: the proxy adds this token
    token = "you@example.com:ATATT3..."
    allow = ["GET", "POST /wiki/api/v2/footer-comments"]
    mutations = ["addComment"]              # optional: GraphQL mutations by name

Every entry of `allow` is "METHODS [PATH]". METHODS is a comma separated list
of GET (which includes HEAD), POST, PUT, PATCH, DELETE, OPTIONS, git-fetch,
git-push, graphql (queries only), or * (everything). PATH is matched against
the request path without the query string: * stands for one path segment,
** for any number of them, and no PATH means every path. For git-fetch and
git-push the PATH is the repository path. Entries only allow; the request
passes if any entry allows it, in whatever order they are written.

A host is either an exact name or "*.name" for its subdomains. An exact
entry wins over a wildcard one; entries are not merged.

This module has no mitmproxy in it, so it can be tested on its own and used
by `ssbx check`.
"""

import base64
import ipaddress
import json
import re
import urllib.parse

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
SPECIAL = ("git-fetch", "git-push", "graphql", "*")
KINDS = ("gitlab", "github", "atlassian", "bearer")

# Names that are never a valid host for the sandbox, whatever the file says.
RESERVED_NAMES = {"localhost", "host.lima.internal", "host.docker.internal", "ssbx.audit"}
RESERVED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".arpa", ".onion")

LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
PATH_SEGMENT_OK = re.compile(r"^[A-Za-z0-9._~%+@:,!$&'()=*-]*$")
PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
ID_LIKE = re.compile(r"^(\d{2,}|[0-9a-f]{8,}|[0-9a-fA-F-]{32,36}|.*%.*)$")
GRAPHQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")


class ConfigError(Exception):
    """Something in the [hosts] tables is wrong. The message says what."""


class Decision:
    __slots__ = ("allowed", "reason", "rule", "suggest")

    def __init__(self, allowed, reason="", rule=None, suggest=None):
        self.allowed = allowed
        self.reason = reason
        self.rule = rule
        self.suggest = suggest

    def __repr__(self):
        return f"Decision({'allow' if self.allowed else 'block'}, {self.reason!r}, rule={self.rule!r})"


# ------------------------------------------------------------------ hosts

def is_ip_literal(name):
    """True for an IP address in any spelling: 10.0.0.1, 127.1, 0x7f000001, ::1."""
    bare = name.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        pass
    if ":" in bare:
        return True  # looks like IPv6 and did not parse: still not a name
    labels = bare.split(".")
    if all(re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", label) for label in labels if label):
        return True  # only numbers: the old inet_aton spellings
    return False


def normalize_host(name):
    """Lowercase, no trailing dot, punycode for non-ASCII names."""
    name = name.strip().rstrip(".").lower()
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        name = name.encode("idna").decode("ascii")
    return name


def check_host_name(name, where):
    """Raise ConfigError unless name is a host the sandbox may be given."""
    if name.startswith("*."):
        rest = name[2:]
        if rest.count(".") < 1:
            raise ConfigError(f'{where}: "*.{rest}" is too wide, a wildcard needs at least two labels after it')
        if "*" in rest:
            raise ConfigError(f'{where}: only one "*." at the start of a name is allowed')
        name = rest
    if "*" in name:
        raise ConfigError(f'{where}: "*" can only be the first label, as in *.example.com')
    if "." not in name:
        raise ConfigError(f"{where}: a host needs a dot, single names are not reachable from the sandbox")
    if is_ip_literal(name):
        raise ConfigError(f"{where}: IP addresses are not allowed, name the host")
    if name in RESERVED_NAMES or name.endswith(RESERVED_SUFFIXES):
        raise ConfigError(f"{where}: {name} points at your own machine or network and is never reachable")
    for label in name.split("."):
        if not LABEL.match(label):
            raise ConfigError(f"{where}: {name!r} is not a valid host name")


def address_is_reachable(address):
    """False for addresses that are your own machine, the VM's network, link-local
    and the like. Intranet (RFC 1918) addresses are fine: the host is in your file."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return False
    if ip.version == 4 and ip in ipaddress.ip_network("192.168.5.0/24"):
        return False  # Lima's user network: the VM and the host gateway
    return True


# ------------------------------------------------------------------ paths

def normalize_path(path):
    """A request path (or rule path) in one spelling: %XX upper-cased, one
    trailing slash dropped, empty is /."""
    path = path.split("?", 1)[0].split("#", 1)[0] or "/"
    path = PERCENT.sub(lambda m: m.group().upper(), path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def why_unusual_path(path):
    """The reason a raw request path is refused before any rule is looked at."""
    if not path.startswith("/"):
        return "the path does not start with /"
    if any(ord(c) < 33 or ord(c) == 127 for c in path):
        return "the path contains control characters or spaces"
    path = path.split("?", 1)[0]  # the rest is the query, which the rules do not look at
    if "\\" in path or ";" in path:
        return "the path contains a backslash or a semicolon"
    if "//" in path:
        return "the path contains a doubled slash"
    for m in PERCENT.finditer(path):
        code = int(m.group()[1:], 16)
        if code < 32 or code == 127:
            return "the path percent-encodes a control character"
        if chr(code) in UNRESERVED or code == 0x5C:
            return "the path percent-encodes a plain character, which servers decode differently"
    for segment in path.split("/"):
        if segment in (".", ".."):
            return "the path contains . or .."
    return None


def compile_path(pattern, where):
    """Turn a rule path into a regex. * is one segment, ** any number of them."""
    if not pattern.startswith("/"):
        raise ConfigError(f"{where}: the path must start with /")
    if any(c in pattern for c in "?# \t"):
        raise ConfigError(f"{where}: the path cannot contain spaces, ? or #")
    if "//" in pattern or "\\" in pattern:
        raise ConfigError(f"{where}: the path cannot contain // or a backslash")
    pattern = normalize_path(pattern)
    parts = []
    for segment in pattern.split("/")[1:]:
        if segment == "**":
            parts.append("(?:/[^/]+)*")
        elif "**" in segment:
            raise ConfigError(f"{where}: ** has to be a whole segment, as in /a/**")
        elif segment in (".", ".."):
            raise ConfigError(f"{where}: the path cannot contain . or ..")
        elif not PATH_SEGMENT_OK.match(segment):
            raise ConfigError(f"{where}: unusual characters in the path")
        elif segment == "*":
            parts.append("/[^/]+")
        else:
            parts.append("/" + "[^/]*".join(re.escape(piece) for piece in segment.split("*")))
    body = "".join(parts)
    if re.fullmatch(body, ""):
        body = f"(?:/|{body})"  # /** and the like also mean the root itself
    return re.compile("^" + body + "$")


# ------------------------------------------------------------------ rules

class Rule:
    def __init__(self, text, methods, path, regex):
        self.text = text          # as written, for the log
        self.methods = methods    # set of method tokens
        self.path = path          # the pattern or None
        self.regex = regex        # compiled or None

    def matches_path(self, path):
        return self.regex is None or self.regex.match(normalize_path(path)) is not None

    def allows(self, method, path):
        """method is a request method or one of git-fetch, git-push, graphql."""
        if "*" in self.methods:
            return self.matches_path(path)
        if method == "HEAD":
            method = "GET"
        return method in self.methods and self.matches_path(path)


def parse_rule(text, where):
    if not isinstance(text, str) or not text.strip():
        raise ConfigError(f"{where}: every allow entry is a string like \"GET\" or \"POST /path\"")
    parts = text.split()
    if len(parts) > 2:
        raise ConfigError(f"{where}: {text!r} has more than a method list and a path; one entry per rule")
    methods = set()
    for token in parts[0].split(","):
        token = token.strip()
        upper = token.upper()
        if upper in METHODS:
            methods.add(upper)
        elif token.lower() in SPECIAL:
            methods.add(token.lower())
        elif upper == "HEAD":
            methods.add("GET")
        else:
            raise ConfigError(f"{where}: unknown method {token!r} in {text!r} "
                              f"(use GET POST PUT PATCH DELETE OPTIONS git-fetch git-push graphql or *)")
    path = None
    regex = None
    if len(parts) == 2:
        path = parts[1]
        regex = compile_path(path, f"{where}: {text!r}")
    return Rule(text, methods, path, regex)


class Host:
    def __init__(self, name, where):
        self.name = name
        self.where = where
        self.wildcard = name.startswith("*.")
        self.kind = None
        self.token = None
        self.mutations = set()
        self.rules = []

    @property
    def tunnel(self):
        """No token and "*" on every path: the proxy does not look inside."""
        return self.token is None and any("*" in r.methods and r.path is None for r in self.rules)

    @property
    def mode(self):
        if self.token is not None:
            return "token"
        return "tunnel" if self.tunnel else "intercept"

    def allowing(self, method, path):
        for rule in self.rules:
            if rule.allows(method, path):
                return rule
        return None


def load(hosts_table):
    """Build the allowlist from the [hosts] tables (a dict, as tomllib gives it)."""
    if hosts_table is None:
        hosts_table = {}
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
        if isinstance(allow, str):
            allow = [allow]
        if not isinstance(allow, list):
            raise ConfigError(f"{where}: allow must be a string or a list of strings")
        for text in allow:
            host.rules.append(parse_rule(text, where))

        kind, token = table.get("kind"), table.get("token")
        if (kind is None) != (token is None):
            raise ConfigError(f"{where}: kind and token go together")
        if kind is not None:
            if kind not in KINDS:
                raise ConfigError(f"{where}: kind must be one of {', '.join(KINDS)}")
            if not isinstance(token, str) or not token.strip():
                raise ConfigError(f"{where}: token must be a non-empty string")
            if host.wildcard:
                raise ConfigError(f"{where}: a token needs an exact host, not a wildcard")
            if kind == "atlassian" and ":" not in token:
                raise ConfigError(f"{where}: an atlassian token is written email:api-token")
            host.kind, host.token = kind, token.strip()
            auth_headers(kind, host.token, False)  # a bad token shape fails here, not on first use

        mutations = table.get("mutations", [])
        if isinstance(mutations, str):
            mutations = [mutations]
        if not isinstance(mutations, list) or not all(isinstance(m, str) and m.strip() for m in mutations):
            raise ConfigError(f"{where}: mutations must be a list of GraphQL mutation names")
        for m in mutations:
            m = m.strip()
            if not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z*]*", m):
                raise ConfigError(f"{where}: {m!r} is not a mutation name")
            host.mutations.add(m)

        if host.wildcard:
            wildcards.append(host)
        else:
            if name in exact:
                raise ConfigError(f"{where} is listed twice")
            exact[name] = host
    wildcards.sort(key=lambda h: -len(h.name))  # the most specific wildcard first
    return Rules(exact, wildcards)


class Rules:
    def __init__(self, exact, wildcards):
        self.exact = exact
        self.wildcards = wildcards

    def hosts(self):
        return list(self.exact.values()) + list(self.wildcards)

    def find(self, host):
        host = normalize_host(host)
        if host in self.exact:
            return self.exact[host]
        for entry in self.wildcards:
            if host.endswith(entry.name[1:]) and host != entry.name[2:]:
                return entry
        return None

    def warnings(self):
        out = []
        for host in self.hosts():
            if host.token is not None and not host.rules:
                out.append(f"{host.where} has a token but no allow entry, so nothing is reachable there")
            if host.mutations and not any("graphql" in r.methods or "*" in r.methods for r in host.rules):
                out.append(f"{host.where} lists mutations but no graphql entry")
            if host.wildcard and any(m in r.methods for r in host.rules
                                     for m in ("POST", "PUT", "PATCH", "DELETE", "git-push", "*")):
                out.append(f"{host.where} allows writes on every subdomain")
        if "api.anthropic.com" not in self.exact:
            out.append("api.anthropic.com is not listed, so Claude Code cannot reach Anthropic")
        return out

    def decide(self, host, method, path, git=None, graphql=None):
        """Decide one request.
        git: None, "fetch" or "push" when the request is git smart HTTP; then
             path is the repository path.
        graphql: None, or the list of operations of a GraphQL document as
             graphql_operations() returns them."""
        entry = self.find(host)
        if entry is None:
            name = normalize_host(host)
            if is_ip_literal(name) or name in RESERVED_NAMES or name.endswith(RESERVED_SUFFIXES) or "." not in name:
                return Decision(False, f"{name} is an address or a local name, never reachable from the sandbox")
            return Decision(False, f"{name} is not in your allowlist",
                            suggest=suggest(host, method, path, git, graphql))
        if git is not None:
            wanted = "git-fetch" if git == "fetch" else "git-push"
            rule = entry.allowing(wanted, path)
            if rule is None:
                return Decision(False, f"git {git} to {path} is not allowed on {entry.name}",
                                suggest=suggest(host, method, path, git, graphql))
            return Decision(True, f"{wanted} {path}", rule=rule.text)
        if graphql is not None:
            if method != "POST":
                return Decision(False, "GraphQL is only allowed as POST")
            rule = entry.allowing("graphql", path)
            if rule is None:
                return Decision(False, f"GraphQL on {path} is not allowed on {entry.name}",
                                suggest=suggest(host, method, path, git, graphql))
            if not graphql:
                return Decision(False, "the GraphQL document has no operation to look at")
            if "*" not in rule.methods:
                for kind, names in graphql:
                    if kind == "query":
                        continue
                    if kind == "unknown":
                        return Decision(False, "the GraphQL document could not be read, so it is refused")
                    if kind != "mutation":
                        return Decision(False, f"GraphQL {kind}s are not allowed")
                    refused = [n for n in names if not mutation_allowed(entry, n)]
                    if not names or refused:
                        return Decision(False, "GraphQL mutation " + ", ".join(refused or ["?"]) + " is not allowed"
                                        + f" on {entry.name}", suggest=suggest(host, method, path, git, graphql))
            return Decision(True, f"graphql {path}", rule=rule.text)
        rule = entry.allowing(method, path)
        if rule is None:
            return Decision(False, f"{method} {normalize_path(path)} is not allowed on {entry.name}",
                            suggest=suggest(host, method, path, git, graphql))
        return Decision(True, f"{method} {normalize_path(path)}", rule=rule.text)


def mutation_allowed(entry, name):
    for pattern in entry.mutations:
        if "*" in pattern:
            if re.fullmatch(".*".join(re.escape(p) for p in pattern.split("*")), name):
                return True
        elif pattern == name:
            return True
    return False


def suggest(host, method, path, git=None, graphql=None):
    """A ready-to-paste TOML snippet that would allow this request."""
    host = normalize_host(host)
    if git is not None:
        line = f'allow = "{"git-fetch" if git == "fetch" else "git-push"} {path}"'
    elif graphql is not None:
        names = sorted({n for kind, ns in graphql for n in ns if kind == "mutation"})
        if names:
            line = f'allow = "graphql {normalize_path(path)}"\nmutations = {json.dumps(names)}'
        else:
            line = f'allow = "graphql {normalize_path(path)}"'
    else:
        method = "GET" if method == "HEAD" else method
        segments = normalize_path(path).split("/")[1:]
        generic = "/" + "/".join("*" if ID_LIKE.match(s) else s for s in segments)
        line = f'allow = "{method}"' if method == "GET" else f'allow = "{method} {generic}"'
    return f'[hosts."{host}"]\n{line}'


# ------------------------------------------------------------------ git

GIT_END = re.compile(r"^(?P<repo>/.+?)(?:\.git)?/(?P<what>info/refs|git-upload-pack|git-receive-pack)$")


def git_request(method, path_with_query, content_type=""):
    """(kind, repo) for git smart HTTP requests, else None.
    kind is "fetch" for clone/fetch/ls-remote, "push" for push."""
    path, _, query = path_with_query.partition("?")
    if path.startswith("/api/"):
        return None  # GitLab's API takes the last part for a file name there
    m = GIT_END.match(path)
    if not m:
        return None
    what, repo = m.group("what"), m.group("repo")
    if what == "info/refs":
        if method != "GET":
            return None
        service = dict(p.split("=", 1) for p in query.split("&") if "=" in p).get("service", "")
        if service == "git-upload-pack":
            return "fetch", repo
        if service == "git-receive-pack":
            return "push", repo
        return None
    if method != "POST" or not content_type.lower().startswith(f"application/x-{what}-request"):
        return None
    return ("fetch" if what == "git-upload-pack" else "push"), repo


# ------------------------------------------------------------------ graphql

def is_graphql_path(path):
    return normalize_path(path).split("/")[-1].lower() == "graphql"


def graphql_operations(body, limit=1024 * 1024):
    """The operations in a GraphQL request body: a list of (kind, top-level
    field names). kind is query, mutation, subscription, or unknown when the
    document could not be read. Raises ValueError when the body is not a
    GraphQL request (bad JSON, a persisted query without text, too big)."""
    if len(body) > limit:
        raise ValueError("body too big")
    document = json.loads(body)
    requests = document if isinstance(document, list) else [document]
    if not requests:
        raise ValueError("empty batch")
    operations = []
    for item in requests:
        if not isinstance(item, dict) or not isinstance(item.get("query"), str):
            raise ValueError("no query text")
        operations.extend(parse_document(item["query"]))
    return operations


def parse_document(text):
    """A light reading of a GraphQL document: which operations it holds and,
    for each, the names of its top-level fields. Anything it cannot follow
    comes back as ("unknown", [])."""
    # Strings and comments cannot carry keywords once they are blanked out.
    text = re.sub(r'"""(?:.|\n)*?"""', '""', text)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    text = re.sub(r"#[^\n]*", "", text)
    text = text.replace(",", " ")
    ops = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        m = GRAPHQL_NAME.match(text, i)
        if m and m.group() in ("query", "mutation", "subscription", "fragment"):
            keyword = m.group()
            i = m.end()
            if keyword == "fragment":
                i = skip_to_selection(text, i)
                if i < 0:
                    return [("unknown", [])]
                i = skip_block(text, i)
                if i < 0:
                    return [("unknown", [])]
                continue
            i = skip_to_selection(text, i)
            if i < 0:
                return [("unknown", [])]
            names, i = top_level_fields(text, i)
            if i < 0:
                return [("unknown", [])]
            ops.append((keyword, names))
        elif text[i] == "{":
            names, i = top_level_fields(text, i)
            if i < 0:
                return [("unknown", [])]
            ops.append(("query", names))
        else:
            return [("unknown", [])]
    return ops or [("unknown", [])]


def skip_to_selection(text, i):
    """From after an operation keyword, past the name, variables and
    directives, to the opening brace of the selection set. -1 if lost."""
    n = len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "(":
            i = skip_block(text, i, "(", ")")
            if i < 0:
                return -1
        elif c == "@":
            i += 1
        elif c == "{":
            return i
        elif GRAPHQL_NAME.match(text, i):
            i = GRAPHQL_NAME.match(text, i).end()
        elif c == ":" or c == "!" or c == "$" or c == "[" or c == "]" or c == "=":
            i += 1
        else:
            return -1
    return -1


def skip_block(text, i, open_="{", close="}"):
    """From an opening bracket at i to just after its matching close. -1 if unbalanced."""
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def top_level_fields(text, i):
    """Names of the fields directly inside the selection set starting at text[i] == '{'.
    Returns (names, index after the set); names is None when a fragment spread
    or something unreadable sits at the top level."""
    assert text[i] == "{"
    i += 1
    names = []
    n = len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "}":
            return names, i + 1
        elif c == ".":
            return [], -1  # a fragment spread: we cannot see what it does
        elif c == "@":
            i += 1
            m = GRAPHQL_NAME.match(text, i)
            i = m.end() if m else i
            if i < n and text[i] == "(":
                i = skip_block(text, i, "(", ")")
                if i < 0:
                    return [], -1
        else:
            m = GRAPHQL_NAME.match(text, i)
            if not m:
                return [], -1
            name = m.group()
            i = m.end()
            while i < n and text[i].isspace():
                i += 1
            if i < n and text[i] == ":":  # alias: the real field follows
                i += 1
                while i < n and text[i].isspace():
                    i += 1
                m = GRAPHQL_NAME.match(text, i)
                if not m:
                    return [], -1
                name = m.group()
                i = m.end()
            names.append(name)
            while i < n:
                while i < n and text[i].isspace():
                    i += 1
                if i < n and text[i] == "(":
                    i = skip_block(text, i, "(", ")")
                    if i < 0:
                        return [], -1
                elif i < n and text[i] == "@":
                    i += 1
                    m = GRAPHQL_NAME.match(text, i)
                    i = m.end() if m else i
                elif i < n and text[i] == "{":
                    i = skip_block(text, i)
                    if i < 0:
                        return [], -1
                    break
                else:
                    break
    return [], -1


# ------------------------------------------------------------------ tokens

def basic_auth(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def auth_headers(kind, token, is_git):
    """The header that carries the token, in the form each service expects."""
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


# Endpoints that turn a token into other credentials. Never reachable with a token.
CREDENTIAL_PATHS = ("/jwt/", "/oauth/", "/-/", "/login", "/session", "/users/sign_in", "/access_tokens",
                    "/personal_access_tokens", "/api/v4/personal_access_tokens", "/settings/tokens")


def hands_out_credentials(path):
    for p in (normalize_path(path), urllib.parse.unquote(normalize_path(path))):
        p = p.lower()
        if p.startswith(CREDENTIAL_PATHS) or "/jwt/" in p or "/oauth/" in p or "access_tokens" in p:
            return True
    return False
