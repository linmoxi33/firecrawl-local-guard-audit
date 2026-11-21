import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin", "firecrawl-local-guard-audit")
from importlib.machinery import SourceFileLoader
mod = SourceFileLoader("guard_audit", BIN).load_module()

# Vectors copied from apps/local/src/guard.rs #[cfg(test)] so the port is
# checked against the upstream's own expectations, not invented ones.
UPSTREAM_BLOCKED_PUBLIC_ONLY = [
    "http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
    "http://172.16.0.1/", "http://[::1]/", "http://[fd00::1]/",
    "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/", "http://100.64.0.1/",
    "http://localhost:3000/", "http://foo.localhost/", "http://printer.local/",
]
UPSTREAM_BLOCKED_ALWAYS = [
    "http://169.254.169.254/latest/meta-data/", "http://[fe80::1]/",
    "http://[::ffff:169.254.169.254]/", "http://metadata.google.internal/",
]
UPSTREAM_OK_ALLOW_PRIVATE = [
    "http://127.0.0.1:3000/", "http://localhost:3000/", "http://192.168.1.10/",
]


class TestGuardPort(unittest.TestCase):
    def test_upstream_blocked_vectors_public_only(self):
        for url in UPSTREAM_BLOCKED_PUBLIC_ONLY:
            rec = mod.classify_url(url, "public-only")
            self.assertEqual(rec["verdict"], "blocked", url)

    def test_upstream_public_urls_pass(self):
        for url in ["https://example.com/a", "http://93.184.216.34/"]:
            rec = mod.classify_url(url, "public-only")
            self.assertEqual(rec["verdict"], "ok", url)

    def test_upstream_always_blocked_vectors(self):
        for url in UPSTREAM_BLOCKED_ALWAYS:
            self.assertEqual(mod.classify_url(url, "allow-private")["verdict"], "blocked", url)

    def test_upstream_allow_private_vectors(self):
        for url in UPSTREAM_OK_ALLOW_PRIVATE:
            self.assertEqual(mod.classify_url(url, "allow-private")["verdict"], "ok", url)

    def test_alibaba_metadata_boundary(self):
        self.assertEqual(mod.classify_url("http://100.100.100.200/", "allow-private")["verdict"], "blocked")
        self.assertEqual(mod.classify_url("http://100.100.100.201/", "allow-private")["verdict"], "ok")

    def test_scheme_and_credentials(self):
        for url in ["file:///etc/passwd", "ftp://example.com/", "https://user:pw@example.com/"]:
            self.assertEqual(mod.classify_url(url, "allow-private")["verdict"], "blocked", url)

    def test_public_hostname_is_dns_gate_only(self):
        rec = mod.classify_url("https://internal-gateway.example.com/health", "public-only")
        self.assertEqual(rec["verdict"], "ok")
        self.assertTrue(rec["dns_gate_only"])
        self.assertEqual(rec["rule"], "DNS_RESOLVER_ONLY")

    def test_proxy_turns_dns_gate_into_error(self):
        report = mod.audit_targets(
            ["https://internal-gateway.example.com/health"], "public-only", ["HTTPS_PROXY"])
        self.assertEqual(report["summary"]["proxy_bypass_risk"], 1)
        self.assertEqual(report["findings"][0]["id"], "PROXY_BYPASS_RISK")
        self.assertEqual(report["findings"][0]["severity"], "error")
        self.assertTrue(mod.has_blocking(report))

    def test_no_proxy_keeps_dns_gate_as_info(self):
        report = mod.audit_targets(["https://example.com/"], "public-only", [])
        self.assertEqual(report["findings"][0]["severity"], "info")
        self.assertFalse(mod.has_blocking(report))

    def test_misreported_refusal_detected(self):
        report = mod.audit_responses([os.path.join(ROOT, "examples/in/responses/misreported-refusal.json")])
        self.assertEqual(report["findings"][0]["id"], "MISREPORTED_REFUSAL")
        self.assertEqual(report["findings"][0]["severity"], "error")
        self.assertTrue(mod.has_blocking(report))

    def test_correct_refusal_is_info_only(self):
        report = mod.audit_responses([os.path.join(ROOT, "examples/in/responses/correct-refusal.json")])
        self.assertEqual(report["findings"][0]["id"], "REFUSAL_REPORTED")
        self.assertFalse(mod.has_blocking(report))


class TestCliBehaviour(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, BIN, *args], capture_output=True, text=True)

    def test_targets_exit_1_and_json_parses(self):
        p = self.run_cli("targets", os.path.join(ROOT, "examples/in/targets.txt"), "--json")
        self.assertEqual(p.returncode, 1)
        data = json.loads(p.stdout)
        self.assertEqual(data["summary"]["targets"], 5)
        self.assertEqual(data["summary"]["blocked"], 3)

    def test_clean_targets_exit_0(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("https://example.com/\nhttp://93.184.216.34/\n")
            path = fh.name
        try:
            p = self.run_cli("targets", path, "--json")
            self.assertEqual(p.returncode, 0)
            self.assertEqual(json.loads(p.stdout)["findings"][0]["severity"], "info")
        finally:
            os.unlink(path)

    def test_missing_file_exit_2(self):
        p = self.run_cli("targets", "/nonexistent/targets.txt")
        self.assertEqual(p.returncode, 2)

    def test_bad_json_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            p = self.run_cli("responses", path)
            self.assertEqual(p.returncode, 2)
        finally:
            os.unlink(path)

    def test_responses_exit_1(self):
        p = self.run_cli("responses", *[os.path.join(ROOT, "examples/in/responses", f)
                                        for f in sorted(os.listdir(os.path.join(ROOT, "examples/in/responses")))], "--json")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(json.loads(p.stdout)["summary"]["misreported_refusals"], 1)

    def test_report_matches_examples_out(self):
        out = tempfile.mktemp(suffix=".json")
        try:
            self.run_cli("targets", os.path.join(ROOT, "examples/in/targets.txt"), "--json", "--out", out)
            with open(out) as fh:
                got = json.load(fh)
            with open(os.path.join(ROOT, "examples/out/targets.report.json")) as fh:
                want = json.load(fh)
            self.assertEqual(got, want)
        finally:
            if os.path.exists(out):
                os.unlink(out)

    def test_replay_is_byte_identical(self):
        a = self.run_cli("targets", os.path.join(ROOT, "examples/in/targets.txt"), "--proxy-var", "HTTPS_PROXY", "--json")
        b = self.run_cli("targets", os.path.join(ROOT, "examples/in/targets.txt"), "--proxy-var", "HTTPS_PROXY", "--json")
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(a.returncode, 1)

    def test_allow_private_policy_via_cli(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("http://127.0.0.1:3000/\n")
            path = fh.name
        try:
            p = self.run_cli("targets", path, "--policy", "allow-private", "--json")
            self.assertEqual(p.returncode, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
