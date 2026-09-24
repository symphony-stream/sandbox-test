"""Tests for the allowlist engine. Run: python3 -m unittest"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "proxy"))

import rules  # noqa: E402
from rules import ConfigError, load  # noqa: E402

EXAMPLE = {
    "api.anthropic.com": {"allow": "*"},
    "registry.npmjs.org": {"allow": "GET"},
    "deb.debian.org": {"allow": ["GET"]},
    "github.com": {"kind": "github", "token": "ghp_x", "allow": ["GET,git-fetch", "git-push /me/scratch"]},
    "*.githubusercontent.com": {"allow": "GET"},
    "api.github.com": {"kind": "github", "token": "ghp_x", "allow": ["GET,graphql"], "mutations": ["addComment"]},
    "gitlab.example.com": {"kind": "gitlab", "token": "glpat-x",
                           "allow": ["GET,git-fetch,graphql /api/graphql", "POST /api/v4/projects/*/merge_requests/*/notes"]},
    "example.atlassian.net": {"kind": "atlassian", "token": "me@example.com:tok",
                              "allow": ["GET", "POST /wiki/api/v2/footer-comments", "POST /rest/api/3/search/jql"]},
    "wide.example.com": {"allow": ["* /api/**"]},
}


class Parsing(unittest.TestCase):
    def test_example_loads(self):
        r = load(EXAMPLE)
        self.assertEqual(r.find("api.anthropic.com").mode, "tunnel")
        self.assertEqual(r.find("registry.npmjs.org").mode, "intercept")
        self.assertEqual(r.find("github.com").mode, "token")
        self.assertEqual(r.find("wide.example.com").mode, "intercept")  # * with a path is looked at
        self.assertEqual(r.find("raw.githubusercontent.com").name, "*.githubusercontent.com")
        self.assertEqual(r.find("a.b.githubusercontent.com").name, "*.githubusercontent.com")
        self.assertIsNone(r.find("githubusercontent.com"))
        self.assertIsNone(r.find("evil.com"))
        self.assertEqual(r.find("API.GitHub.com.").name, "api.github.com")

    def test_allow_string_or_list(self):
        self.assertEqual(len(load({"a.example.com": {"allow": "GET"}}).find("a.example.com").rules), 1)
        self.assertEqual(len(load({"a.example.com": {"allow": ["GET", "POST /x"]}}).find("a.example.com").rules), 2)
        self.assertEqual(len(load({"a.example.com": {}}).find("a.example.com").rules), 0)

    def test_bad_entries(self):
        bad = [
            {"a.example.com": {"allow": "FOO"}},
            {"a.example.com": {"allow": "GET /a /b"}},
            {"a.example.com": {"allow": "GET a"}},
            {"a.example.com": {"allow": "GET /a?x=1"}},
            {"a.example.com": {"allow": "GET /a/b**"}},
            {"a.example.com": {"allow": "GET /a//b"}},
            {"a.example.com": {"allow": "GET /../b"}},
            {"a.example.com": {"allow": 3}},
            {"a.example.com": {"allow": "GET", "extra": 1}},
            {"a.example.com": {"kind": "github"}},
            {"a.example.com": {"kind": "nope", "token": "x"}},
            {"a.example.com": {"kind": "atlassian", "token": "no-colon"}},
            {"*.example.com": {"kind": "github", "token": "x"}},
            {"a.example.com": {"mutations": [3]}},
            {"a.example.com": {"mutations": ["bad name"]}},
            {"localhost": {"allow": "*"}},
            {"nodots": {"allow": "*"}},
            {"10.0.0.1": {"allow": "*"}},
            {"127.1": {"allow": "*"}},
            {"0x7f.1": {"allow": "*"}},
            {"[::1]": {"allow": "*"}},
            {"host.lima.internal": {"allow": "*"}},
            {"printer.local": {"allow": "*"}},
            {"ssbx.audit": {"allow": "*"}},
            {"*.com": {"allow": "GET"}},
            {"*": {"allow": "GET"}},
            {"a*.example.com": {"allow": "GET"}},
            {"a.example.com": "GET"},
            {"bad_name.example.com": {"allow": "GET"}},
        ]
        for table in bad:
            with self.subTest(table=table):
                with self.assertRaises(ConfigError):
                    load(table)

    def test_warnings(self):
        r = load({"a.example.com": {"kind": "bearer", "token": "x"},
                  "b.example.com": {"allow": "GET", "mutations": ["x"]},
                  "*.c.example.com": {"allow": "POST"}})
        text = "\n".join(r.warnings())
        self.assertIn("token but no allow", text)
        self.assertIn("mutations but no graphql", text)
        self.assertIn("writes on every subdomain", text)
        self.assertIn("api.anthropic.com", text)
        self.assertEqual(load(EXAMPLE).warnings(), [])


class Paths(unittest.TestCase):
    def match(self, pattern, path):
        return rules.compile_path(pattern, "t").match(rules.normalize_path(path)) is not None

    def test_wildcards(self):
        self.assertTrue(self.match("/a/*/b", "/a/1/b"))
        self.assertFalse(self.match("/a/*/b", "/a/1/2/b"))
        self.assertFalse(self.match("/a/*/b", "/a//b"))
        self.assertTrue(self.match("/a/**", "/a"))
        self.assertTrue(self.match("/a/**", "/a/"))
        self.assertTrue(self.match("/a/**", "/a/b/c"))
        self.assertFalse(self.match("/a/**", "/ab"))
        self.assertTrue(self.match("/**", "/"))
        self.assertTrue(self.match("/**", "/x/y"))
        self.assertTrue(self.match("/", "/"))
        self.assertFalse(self.match("/", "/x"))
        self.assertTrue(self.match("/repos/*/*/issues/*/comments", "/repos/o/r/issues/12/comments"))
        self.assertTrue(self.match("/api/v4/projects/*/notes", "/api/v4/projects/group%2Frepo/notes"))
        self.assertTrue(self.match("/x/*.json", "/x/a.json"))
        self.assertFalse(self.match("/x/*.json", "/x/a.jsonx"))

    def test_query_and_case(self):
        self.assertTrue(self.match("/a", "/a?x=1"))
        self.assertTrue(self.match("/a", "/a/"))
        self.assertFalse(self.match("/a", "/A"))
        self.assertTrue(self.match("/a%2fb", "/a%2Fb"))

    def test_unusual(self):
        for p in ("/a/../b", "/a/./b", "/a//b", "/a;b", "/a\\b", "/a b", "/a\x01", "/a/%2e%2e/b", "/a%5cb", "/%6Awt", "/a%00", "a"):
            self.assertIsNotNone(rules.why_unusual_path(p), p)
        for p in ("/", "/a/b.c", "/a%20b", "/repos/a%2Fb", "/x?y=/../z", "/caf%C3%A9"):
            self.assertIsNone(rules.why_unusual_path(p), p)


class Decisions(unittest.TestCase):
    def setUp(self):
        self.r = load(EXAMPLE)

    def decide(self, host, method, path, **kw):
        return self.r.decide(host, method, path, **kw)

    def test_plain(self):
        self.assertTrue(self.decide("registry.npmjs.org", "GET", "/react").allowed)
        self.assertTrue(self.decide("registry.npmjs.org", "HEAD", "/react").allowed)
        self.assertFalse(self.decide("registry.npmjs.org", "POST", "/-/v1/login").allowed)
        self.assertFalse(self.decide("registry.npmjs.org", "OPTIONS", "/").allowed)
        self.assertTrue(self.decide("api.anthropic.com", "DELETE", "/anything").allowed)
        self.assertTrue(self.decide("raw.githubusercontent.com", "GET", "/o/r/main/x").allowed)
        self.assertFalse(self.decide("raw.githubusercontent.com", "PUT", "/o/r/main/x").allowed)
        self.assertTrue(self.decide("wide.example.com", "PATCH", "/api/x").allowed)
        self.assertFalse(self.decide("wide.example.com", "GET", "/other").allowed)

    def test_unknown_host(self):
        d = self.decide("evil.com", "GET", "/x")
        self.assertFalse(d.allowed)
        self.assertIn("not in your allowlist", d.reason)
        self.assertEqual(d.suggest, '[hosts."evil.com"]\nallow = "GET"')
        for host in ("127.0.0.1", "10.0.0.1", "localhost", "host.lima.internal", "printer.local", "nodots"):
            d = self.decide(host, "GET", "/x")
            self.assertFalse(d.allowed)
            self.assertIsNone(d.suggest, host)

    def test_suggest(self):
        d = self.decide("example.atlassian.net", "POST", "/wiki/api/v2/pages/123456/footer-comments")
        self.assertFalse(d.allowed)
        self.assertEqual(d.suggest, '[hosts."example.atlassian.net"]\nallow = "POST /wiki/api/v2/pages/*/footer-comments"')
        d = self.decide("example.atlassian.net", "DELETE", "/rest/api/3/issue/ABC-1?x=1")
        self.assertEqual(d.suggest, '[hosts."example.atlassian.net"]\nallow = "DELETE /rest/api/3/issue/ABC-1"')
        d = self.decide("example.atlassian.net", "PUT", "/x/deadbeef1234/y/550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(d.suggest.splitlines()[1], 'allow = "PUT /x/*/y/*"')

    def test_endpoint_rules(self):
        self.assertTrue(self.decide("example.atlassian.net", "GET", "/wiki/rest/api/content").allowed)
        self.assertTrue(self.decide("example.atlassian.net", "POST", "/wiki/api/v2/footer-comments").allowed)
        self.assertTrue(self.decide("example.atlassian.net", "POST", "/rest/api/3/search/jql").allowed)
        self.assertFalse(self.decide("example.atlassian.net", "POST", "/rest/api/3/issue").allowed)
        self.assertFalse(self.decide("example.atlassian.net", "POST", "/wiki/api/v2/footer-comments/1").allowed)
        self.assertFalse(self.decide("example.atlassian.net", "DELETE", "/wiki/api/v2/footer-comments").allowed)
        self.assertTrue(self.decide("gitlab.example.com", "POST", "/api/v4/projects/12/merge_requests/3/notes").allowed)
        self.assertFalse(self.decide("gitlab.example.com", "POST", "/api/v4/projects/12/merge_requests/3/notes/4").allowed)
        self.assertFalse(self.decide("gitlab.example.com", "POST", "/api/v4/projects/12/merge_requests").allowed)

    def test_git(self):
        self.assertTrue(self.decide("github.com", "GET", "/o/r", git="fetch").allowed)
        self.assertFalse(self.decide("github.com", "POST", "/o/r", git="push").allowed)
        self.assertTrue(self.decide("github.com", "POST", "/me/scratch", git="push").allowed)
        self.assertFalse(self.decide("github.com", "POST", "/me/scratch2", git="push").allowed)
        # POST does not allow a push, GET does not allow a fetch
        self.assertFalse(self.decide("example.atlassian.net", "POST", "/o/r", git="push").allowed)
        self.assertFalse(self.decide("example.atlassian.net", "GET", "/o/r", git="fetch").allowed)
        self.assertTrue(self.decide("api.anthropic.com", "POST", "/o/r", git="push").allowed)  # * allows all
        d = self.decide("registry.npmjs.org", "GET", "/o/r", git="fetch")
        self.assertEqual(d.suggest, '[hosts."registry.npmjs.org"]\nallow = "git-fetch /o/r"')

    def test_git_request(self):
        self.assertEqual(rules.git_request("GET", "/o/r.git/info/refs?service=git-upload-pack"), ("fetch", "/o/r"))
        self.assertEqual(rules.git_request("GET", "/o/r/info/refs?service=git-receive-pack"), ("push", "/o/r"))
        self.assertEqual(rules.git_request("POST", "/o/r.git/git-upload-pack", "application/x-git-upload-pack-request"), ("fetch", "/o/r"))
        self.assertEqual(rules.git_request("POST", "/o/r/git-receive-pack", "application/x-git-receive-pack-request"), ("push", "/o/r"))
        self.assertIsNone(rules.git_request("POST", "/o/r/git-receive-pack", "application/json"))
        self.assertIsNone(rules.git_request("POST", "/o/r/git-upload-pack", ""))
        self.assertIsNone(rules.git_request("GET", "/o/r/info/refs"))
        self.assertIsNone(rules.git_request("GET", "/api/v4/projects/1/repository/files/git-upload-pack"))
        self.assertIsNone(rules.git_request("GET", "/api/v4/x/info/refs?service=git-upload-pack"))
        self.assertIsNone(rules.git_request("POST", "/o/r/info/refs?service=git-upload-pack"))

    def test_graphql(self):
        ops = rules.graphql_operations(b'{"query": "query { viewer { login } }"}')
        self.assertEqual(ops, [("query", ["viewer"])])
        self.assertTrue(self.decide("api.github.com", "POST", "/graphql", graphql=ops).allowed)
        self.assertFalse(self.decide("api.github.com", "GET", "/graphql", graphql=ops).allowed)
        self.assertFalse(self.decide("github.com", "POST", "/graphql", graphql=ops).allowed)  # no graphql rule
        ops = rules.graphql_operations(b'{"query": "\\u006dutation { addReaction(input:{subjectId:\\"x\\"}) { subject { id } } }"}')
        self.assertEqual(ops, [("mutation", ["addReaction"])])
        d = self.decide("api.github.com", "POST", "/graphql", graphql=ops)
        self.assertFalse(d.allowed)
        self.assertIn("addReaction", d.reason)
        self.assertEqual(d.suggest, '[hosts."api.github.com"]\nallow = "graphql /graphql"\nmutations = ["addReaction"]')
        ops = rules.graphql_operations(b'{"query": "mutation Add($input: AddCommentInput!) { c: addComment(input: $input) { subject { id } } }"}')
        self.assertEqual(ops, [("mutation", ["addComment"])])
        self.assertTrue(self.decide("api.github.com", "POST", "/graphql", graphql=ops).allowed)
        ops = rules.graphql_operations(b'{"query": "mutation { addComment(input: {b: \\"}\\"}) { id } deleteIssue(input: {}) { id } }"}')
        self.assertEqual(ops, [("mutation", ["addComment", "deleteIssue"])])
        self.assertFalse(self.decide("api.github.com", "POST", "/graphql", graphql=ops).allowed)
        ops = rules.graphql_operations(b'[{"query": "{ a }"}, {"query": "mutation { x }"}]')
        self.assertEqual(ops, [("query", ["a"]), ("mutation", ["x"])])
        ops = rules.graphql_operations(b'{"query": "subscription { x }"}')
        self.assertFalse(self.decide("api.github.com", "POST", "/graphql", graphql=ops).allowed)
        ops = rules.graphql_operations(b'{"query": "mutation { ...Frag } fragment Frag on Mutation { deleteIssue(input: {}) { id } }"}')
        self.assertEqual(ops[0][0], "unknown")
        self.assertFalse(self.decide("api.github.com", "POST", "/graphql", graphql=ops).allowed)
        ops = rules.graphql_operations(b'{"query": "query A { a } mutation B { addComment(input: {}) { id } }"}')
        self.assertTrue(self.decide("api.github.com", "POST", "/graphql", graphql=ops).allowed)
        ops = rules.graphql_operations(b'{"query": "# mutation in a comment\\nquery { viewer { login } }"}')
        self.assertEqual(ops, [("query", ["viewer"])])
        ops = rules.graphql_operations(b'{"query": "query @cached(ttl: 1) { a(id: \\"mutation\\") @include(if: true) { b } }"}')
        self.assertEqual(ops, [("query", ["a"])])
        # everything on a * host, including mutations
        self.assertTrue(self.decide("api.anthropic.com", "POST", "/graphql", graphql=[("mutation", ["x"])]).allowed)
        for body in (b"not json", b'{"extensions": {"persistedQuery": {}}}', b"[]", b'{"query": 3}'):
            with self.assertRaises(ValueError):
                rules.graphql_operations(body)
        with self.assertRaises(ValueError):
            rules.graphql_operations(b'{"query": "{ a }"}', limit=5)
        self.assertTrue(rules.is_graphql_path("/api/graphql?x=1"))
        self.assertTrue(rules.is_graphql_path("/graphql/"))
        self.assertFalse(rules.is_graphql_path("/graphql/x"))

    def test_mutation_patterns(self):
        r = load({"g.example.com": {"allow": "graphql", "mutations": ["add*"]}})
        self.assertTrue(r.decide("g.example.com", "POST", "/graphql", graphql=[("mutation", ["addComment"])]).allowed)
        self.assertFalse(r.decide("g.example.com", "POST", "/graphql", graphql=[("mutation", ["deleteComment"])]).allowed)
        self.assertFalse(r.decide("g.example.com", "POST", "/graphql", graphql=[("mutation", ["addComment", "removeX"])]).allowed)


class Misc(unittest.TestCase):
    def test_ip_literals(self):
        for h in ("10.0.0.1", "127.1", "0177.0.0.1", "0x7f000001", "0x7f.1", "::1", "[::1]", "1.2.3", "2130706433"):
            self.assertTrue(rules.is_ip_literal(h), h)
        for h in ("example.com", "1password.com", "3.example.com", "x1.y2.z3"):
            self.assertFalse(rules.is_ip_literal(h), h)

    def test_reachable(self):
        for a in ("127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "192.168.5.2", "192.168.5.3", "::ffff:127.0.0.1", "fe80::1"):
            self.assertFalse(rules.address_is_reachable(a), a)
        for a in ("93.184.216.34", "10.1.2.3", "192.168.1.10", "172.16.0.5", "2606:4700::1111"):
            self.assertTrue(rules.address_is_reachable(a), a)

    def test_credentials(self):
        for p in ("/jwt/auth", "/%6Awt/auth", "/oauth/token", "/-/profile/personal_access_tokens", "/login", "/session", "/users/sign_in", "/api/v4/personal_access_tokens", "/x/jwt/auth"):
            self.assertTrue(rules.hands_out_credentials(p) or rules.why_unusual_path(p), p)
        for p in ("/api/v4/projects", "/group/repo/-/raw/main/x", "/repos/o/r"):
            self.assertFalse(rules.hands_out_credentials(p), p)

    def test_auth_headers(self):
        self.assertEqual(rules.auth_headers("gitlab", "t", False), {"PRIVATE-TOKEN": "t"})
        self.assertEqual(rules.auth_headers("gitlab", "t", True), {"Authorization": "Basic b2F1dGgyOnQ="})
        self.assertEqual(rules.auth_headers("github", "t", False), {"Authorization": "Bearer t"})
        self.assertEqual(rules.auth_headers("atlassian", "a@b:c", False), {"Authorization": "Basic YUBiOmM="})
        self.assertEqual(rules.auth_headers("bearer", "t", True), {"Authorization": "Bearer t"})


if __name__ == "__main__":
    unittest.main()
