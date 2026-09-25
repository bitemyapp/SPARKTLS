"""Regression tests for accepting invalid measurements and killing other work."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import argparse

import run


def result(marks="***", count=3, response_bytes=0, rc=1):
    return {"rc": rc, "seconds": 3.25, "stderr": "verify depth is 3\n",
            "stdout": f"{marks}\n\n{count} connections in 0.50s; 6.00 connections/user sec, "
                      f"bytes read {count * response_bytes}\n"
                      f"{count} connections in 3 real seconds, {response_bytes} bytes read per connection\n"}


class Measurements(unittest.TestCase):
    def test_successful_openssl_exit_one(self):
        measurement = run.parse_stime(result(), "handshake")
        self.assertEqual(measurement["connections"], 3)
        # The reported integer duration remains metadata, never the rate denominator.
        self.assertNotEqual(result()["seconds"], measurement["openssl_rounded_seconds"])

    def test_reuse_requires_every_connection_resumed(self):
        run.parse_stime(result("rrr", response_bytes=105), "bulk", 105)
        for marks in ("***", "rr*", "rr", "rrrr"):
            with self.subTest(marks=marks), self.assertRaises(RuntimeError):
                run.parse_stime(result(marks, response_bytes=105), "bulk", 105)

    def test_failures_never_become_measurements(self):
        cases = [result(rc=2), result(count=0, marks=""), result("rrr"),
                 result(response_bytes=100)]
        cases += [result() | {"stdout": "partial output"},
                  result() | {"stderr": "error: handshake failed"}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                run.parse_stime(case, "handshake")

    def test_reject_partial_bulk_even_if_average_rounds_down(self):
        measurement = result("rrr", response_bytes=105)
        measurement["stdout"] = measurement["stdout"].replace("bytes read 315", "bytes read 314")
        with self.assertRaises(RuntimeError):
            run.parse_stime(measurement, "bulk", 105)

    def test_probe_requires_exact_negotiation_and_trust(self):
        probe = {"rc": 0, "stdout": "", "stderr": "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\n"
                 "Ciphersuite: TLS_AES_128_GCM_SHA256\nSignature type: ed25519\n"
                 "Verification: OK\nServer Temp Key: X25519, 253 bits\n"}
        run.validate_probe(probe, run.SUITES[0])
        run.validate_probe(probe | {"stderr": probe["stderr"].replace("Server Temp Key", "Negotiated TLS1.3 group")}, run.SUITES[0])
        for value in ("TLSv1.3", "X25519", "ed25519", "Verification: OK", run.SUITES[0]):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                run.validate_probe(probe | {"stderr": probe["stderr"].replace(value, "wrong")}, run.SUITES[0])

    def test_http_checks_body_not_just_size(self):
        body = b"a\x00b\xff"
        digest = hashlib.sha256(body).hexdigest()
        response = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\n" + body
        self.assertEqual(run.validate_http(response, digest, 4)["payload_bytes"], 4)
        for bad in (response[:-1], response[:-1] + b"x", response.replace(b"200", b"404")):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                run.validate_http(bad, digest, 4)

    def test_order_balances_all_three_positions(self):
        orders = [run.order_for(i, run.IMPLEMENTATIONS) for i in range(6)]
        self.assertEqual(len({tuple(order) for order in orders}), 6)
        for position in range(3):
            for name in run.IMPLEMENTATIONS:
                self.assertEqual(sum(order[position] == name for order in orders), 2)

    def test_baseline_order_balances_four_positions(self):
        names = ("sparktls-baseline", *run.IMPLEMENTATIONS)
        orders = [run.order_for(i, names) for i in range(8)]
        for position in range(4):
            for name in names:
                self.assertEqual(sum(order[position] == name for order in orders), 2)

    def test_dependency_copy_does_not_inherit_parent_git_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "SPARKTLS"
            root.mkdir()
            (parent / "sparktlscrypto").mkdir()
            args = argparse.Namespace(implementations=[], openssl="openssl")
            with mock.patch.object(run, "ROOT", root), mock.patch.object(
                    run, "execute", return_value={"rc": 0, "stdout": str(parent) + "\n"}):
                dependency = run.fingerprint(args)["dependencies"]["sparktlscrypto"]
            self.assertTrue(dependency["source_copy"])
            self.assertIsNone(dependency["revision"])

    def test_vendored_rustls_source_is_fingerprinted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "third_party/rustls"
            (vendor / "src").mkdir(parents=True)
            (vendor / "target").mkdir()
            source = vendor / "src/lib.rs"
            source.write_text("// locally patched rustls\n")
            (vendor / "target/generated.rs").write_text("// build output\n")
            out = root / "result"
            out.mkdir()
            with mock.patch.object(run, "ROOT", root), mock.patch.object(run, "HERE", root / "tests/benchmarks"):
                run.source_hashes(out)
            hashes = json.loads((out / "source-sha256.json").read_text())
            self.assertEqual(hashes["third_party/rustls/src/lib.rs"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertNotIn("third_party/rustls/target/generated.rs", hashes)

    def test_warmup_does_not_affect_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            for iteration, rate in [(-1, 100000), (0, 10), (1, 20)]:
                run.record(out, {"scenario": "handshake", "suite": run.SUITES[0],
                                 "implementation": "openssl", "iteration": iteration, "rate": rate})
            run.summarize(out)
            summary = json.loads((out / "summary.json").read_text())[0]
            self.assertEqual(summary["median"], 15)
            self.assertEqual(summary["runs"], 2)
            self.assertEqual(summary["quality"], "exploratory")


class ProcessOwnership(unittest.TestCase):
    def test_cleanup_preserves_unrelated_process(self):
        command = [sys.executable, "-c", "import time; time.sleep(60)"]
        sentinel = subprocess.Popen(command)
        try:
            with tempfile.TemporaryDirectory() as directory:
                server = run.Server(command, directory, os.environ.copy(), Path(directory) / "server.log")
                server.close()
                server.close()  # Cleanup is safe after a prior exit.
                self.assertIsNotNone(server.process.poll())
                self.assertIsNone(sentinel.poll())
        finally:
            sentinel.terminate()
            sentinel.wait()

    def test_failed_fixture_command_leaves_no_success_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            fake_openssl = path / "openssl"
            fake_openssl.write_text(f"#!{sys.executable}\nimport sys\n"
                                    "if sys.argv[1] == 'version':\n"
                                    "    print('OpenSSL 3.0.0 test fixture')\n"
                                    "else:\n    sys.exit(2)\n")
            fake_openssl.chmod(0o700)
            out = path / "result"
            process = subprocess.run([sys.executable, str(run.HERE / "run.py"),
                                      "--implementations", "openssl", "--scenarios", "x509",
                                      "--no-build", "--openssl", str(fake_openssl), "--out", str(out)],
                                     capture_output=True, timeout=30)
            self.assertEqual(process.returncode, 1)
            self.assertFalse(json.loads((out / "status.json").read_text())["complete"])
            self.assertFalse((out / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
