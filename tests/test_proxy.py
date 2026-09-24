"""Tests for the ssbx allowlist. Run: python3 -m unittest"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proxy  # noqa: E402
from proxy import ConfigError, load_rules as load  # noqa: E402

EXAMPLE = {
    "api.anthropic.com": {"allow": "*"},
    "registry.npmjs.org": {"allow": "GET"},
    "github.com": {"kind": "github", "token": "ghp_x",
                   "allow": ["GET,git-fetch", "git-push /me/scratch"]},
    "api.github.com": {"kind": "github", "token": "ghp_x", "allow": ["*", "graphql /graphql"],
                       "mutations": ["addComment"]},
    "wide.example.com": {"allow": "PATCH,GET /api/**"},
}

class Parsing(unittest.TestCase):
    def test_hosts_and_bad_entries(self):
        r = load(EXAMPLE)
        self.assertEqual(r.find("api.anthropic.com").mode, "tunnel")
        self.assertEqual(r.find("github.com").mode, "token")
        self.assertEqual(r.find("API.GitHub.com.").name, "api.github.com")
        bad = [
            {"a.example.com": {"allow": "FOO"}},
            {"a.example.com": {"allow": "GET /a//b"}},
            {"a.example.com": {"kind": "nope", "token": "x"}},
            {"*.example.com": {"kind": "github", "token": "x"}},
            {"localhost": {"allow": "*"}},
            {"10.0.0.1": {"allow": "*"}},
            {"a.example.com": "GET"},
        ]
        for table in bad:
            with self.subTest(table=table):
                with self.assertRaises(ConfigError):
                    load(table)

    def test_method_list(self):
        h = load({"a.example.com": {"allow": "GET,POST /x"}}).find("a.example.com")
        self.assertEqual(h.rules[0].methods, {"GET", "POST"})
        self.assertTrue(proxy.rule_allows(h.rules[0], "HEAD", "/x"))   # HEAD rides on GET
        self.assertTrue(proxy.rule_allows(h.rules[0], "POST", "/x"))
        self.assertFalse(proxy.rule_allows(h.rules[0], "PUT", "/x"))

class Paths(unittest.TestCase):
    def test_percent_decoded_separator(self):
        # %2F decodes to a real "/": a single-segment wildcard no longer
        # swallows it whole, since the decoded path now has two segments.
        h = load({"a.example.com": {"allow": "GET /repos/*/x"}}).find("a.example.com")
        self.assertFalse(proxy.rule_allows(h.rules[0], "GET", "/repos/a%2Fb/x"))
        self.assertTrue(proxy.rule_allows(h.rules[0], "GET", "/repos/a/x"))
        h2 = load({"a.example.com": {"allow": "GET /repos/**"}}).find("a.example.com")
        self.assertTrue(proxy.rule_allows(h2.rules[0], "GET", "/repos/a%2Fb/x"))  # ** still covers any depth

    def test_unusual_paths_refused(self):
        for p in ("/a/../b", "/a/./b", "/a//b", "/a\\b", "/a\x01", "/a/%2e%2e/b", "/a%5c", "/a%25", "a"):
            self.assertIsNotNone(proxy.why_unusual_path(p), p)
        for p in ("/", "/a/b.c", "/a%20b", "/repos/a%2Fb", "/caf%C3%A9"):
            self.assertIsNone(proxy.why_unusual_path(p), p)

class Decisions(unittest.TestCase):
    def setUp(self):
        self.r = load(EXAMPLE)

    def test_wildcard_host(self):
        self.assertTrue(self.r.decide("wide.example.com", "PATCH", "/api/x/y").allowed)
        self.assertTrue(self.r.decide("wide.example.com", "GET", "/api").allowed)
        self.assertFalse(self.r.decide("wide.example.com", "POST", "/api/x").allowed)
        self.assertFalse(self.r.decide("wide.example.com", "GET", "/other").allowed)

    def test_git_fetch_vs_push(self):
        self.assertTrue(self.r.decide("github.com", "GET", "/o/r", git="fetch").allowed)
        self.assertFalse(self.r.decide("github.com", "POST", "/o/r", git="push").allowed)
        self.assertTrue(self.r.decide("github.com", "POST", "/me/scratch", git="push").allowed)
        self.assertFalse(self.r.decide("github.com", "POST", "/me/scratch2", git="push").allowed)
        self.assertEqual(proxy.git_request("GET", "/o/r.git/info/refs?service=git-upload-pack"), ("fetch", "/o/r"))
        self.assertEqual(proxy.git_request("POST", "/o/r/git-receive-pack", "application/x-git-receive-pack-request"),
                         ("push", "/o/r"))
        self.assertIsNone(proxy.git_request("GET", "/o/r/info/refs"))

    def test_mutation_blocked_regardless_of_rule_order(self):
        # api.github.com allows "*" (which would match "graphql" too) before
        # the more specific "graphql /graphql" rule; mutations still has to
        # gate it, not just whichever rule happened to match first.
        blocked = self.r.decide("api.github.com", "POST", "/graphql", graphql=[("mutation", ["deleteEverything"])])
        self.assertFalse(blocked.allowed)
        allowed = self.r.decide("api.github.com", "POST", "/graphql", graphql=[("mutation", ["addComment"])])
        self.assertTrue(allowed.allowed)
        query = self.r.decide("api.github.com", "POST", "/graphql", graphql=[("query", ["viewer"])])
        self.assertTrue(query.allowed)

    def test_suggest_snippet(self):
        d = self.r.decide("evil.com", "GET", "/x")
        self.assertFalse(d.allowed)
        self.assertEqual(d.suggest, '[hosts."evil.com"]\nallow = "GET"')
        d = self.r.decide("registry.npmjs.org", "POST", "/x")
        self.assertEqual(d.suggest, '[hosts."registry.npmjs.org"]\nallow = "POST /x"')
        d = self.r.decide("registry.npmjs.org", "GET", "/o/r", git="fetch")
        self.assertEqual(d.suggest, '[hosts."registry.npmjs.org"]\nallow = "git-fetch /o/r"')

class Misc(unittest.TestCase):
    def test_reachable(self):
        for a in ("127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "192.168.5.2"):
            self.assertFalse(proxy.address_is_reachable(a), a)
        for a in ("93.184.216.34", "10.1.2.3", "172.16.0.5"):
            self.assertTrue(proxy.address_is_reachable(a), a)

    def test_graphql_parses_real_text(self):
        ops = proxy.graphql_operations(b'{"query": "mutation { addComment(input: {b: \\"}\\"}) { id } '
                                        b'deleteIssue(input: {}) { id } }"}')
        self.assertEqual(ops, [("mutation", ["addComment", "deleteIssue"])])
        ops = proxy.graphql_operations(b'{"query": "query { viewer { login } }"}')
        self.assertEqual(ops, [("query", ["viewer"])])

if __name__ == "__main__":
    unittest.main()
