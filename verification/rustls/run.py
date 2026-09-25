#!/usr/bin/env python3
"""Run the pinned Kani contract set and optional proof-pipeline controls."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from verify_vendor import ROOT, VENDOR, verify

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def proof_source_hashes():
    paths = [p for p in VENDOR.rglob("*")
             if p.is_file() and "target" not in p.relative_to(VENDOR).parts]
    paths += [HERE / name for name in (
        "contracts.json", "run.py", "verify_vendor.py", "KANI_VERSION",
        "spark-reference.json",
    )]
    paths += [ROOT / name for name in (
        "ci/rustls_kani.sh", "third_party/rustls-provenance.json",
        "third_party/rustls-upstream-sha256.json",
    )]
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}


def execute(command, log, env, timeout=1200):
    with log.open("w") as output:
        output.write("Command: " + repr(command) + "\n")
        output.flush()
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def results(path):
    report = json.loads(path.read_text())
    return report, report["verification_results"]["results"]


def validate_positive(report, rows, contracts):
    expected = {c["harness"] for c in contracts}
    actual = [r["harness_id"] for r in rows]
    discovered = {h["pretty_name"] for h in report["harness_metadata"]}
    if len(actual) != len(expected) or set(actual) != expected or discovered != expected:
        raise RuntimeError("Harness inventory differs from contracts.json")
    summary = report["verification_results"]["summary"]
    if summary["successful"] != len(expected) or summary["failed"] != 0:
        raise RuntimeError("Incomplete/failed proof summary")
    if any(row["status"] != "Success" for row in rows):
        raise RuntimeError("A proof did not succeed")
    if any(e["has_errors"] for e in report["error_details"]):
        raise RuntimeError("Kani reported a harness error")
    for item in report["property_details"]:
        detail = item["property_details"]
        if any(detail.get(k) != 0 for k in ("failed", "undetermined", "solver_error")):
            raise RuntimeError("Failed, undetermined or solver-error properties")
        if not detail.get("passed"):
            raise RuntimeError("Harness has no checked properties")


def control_failed_as_expected(path, rc, failure_kind):
    report, rows = results(path)
    if rc == 0 or len(rows) != 1 or rows[0]["status"] == "Success":
        raise RuntimeError("Negative control did not fail")
    failed = [c for c in rows[0].get("checks", []) if c["status"] == "Failure"]
    if not any(failure_kind in c["description"].lower() for c in failed):
        raise RuntimeError(f"Control failed for the wrong reason; expected {failure_kind}")
    return {"exit_code": rc, "expected_failure": failure_kind,
            "failed_checks": [c["description"] for c in failed]}


def mutation_control(common, env, out, *, name, harness, file, old, new,
                     occurrences, expected_failure):
    mutant = out / (name + "-mutant")
    shutil.copytree(VENDOR, mutant, ignore=shutil.ignore_patterns("target"))
    source_path = mutant / file
    source = source_path.read_text()
    if source.count(old) != occurrences:
        raise RuntimeError(f"Implementation changed; review {name} mutation control")
    source_path.write_text(source.replace(old, new, 1))
    report = out / (name + ".json")
    rc = execute(common + ["--manifest-path", str(mutant / "Cargo.toml"),
                 "--harness", harness, "--exact", "--export-json", str(report)],
                 out / (name + ".log"), env)
    return control_failed_as_expected(report, rc, expected_failure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="New result directory; never overwritten")
    parser.add_argument("--cargo-kani", default=shutil.which("cargo-kani"))
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--self-test", action="store_true", help="Also require mutation/unwind controls to fail")
    args = parser.parse_args()
    if not args.cargo_kani:
        parser.error("cargo-kani is missing; see verification/rustls/README.md")
    if not 1 <= args.jobs <= 4:
        parser.error("--jobs must be between 1 and 4")
    args.cargo_kani = str(Path(args.cargo_kani).resolve())
    out = (args.out or HERE / "results" / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")).resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    save(out / "status.json", {"complete": False})
    try:
        upstream_files = verify()
        version = (HERE / "KANI_VERSION").read_text().strip()
        text = subprocess.check_output([args.cargo_kani, "kani", "--version"], text=True)
        if f"Kani Rust Verifier {version} " not in text:
            raise RuntimeError(f"Expected Kani {version}; got {text.strip()}")
        env = os.environ.copy()
        env.setdefault("CARGO_BUILD_JOBS", "4")
        contracts = json.loads((HERE / "contracts.json").read_text())
        input_hashes = proof_source_hashes()
        lock_hash = digest(VENDOR / "Cargo.lock")
        # Kani 0.68 has no --locked flag. Check Cargo's lock first and reject
        # any change afterward instead of silently accepting a new resolution.
        subprocess.run(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1",
                        "--manifest-path", str(VENDOR / "Cargo.toml")],
                       cwd=ROOT, env=env, stdout=subprocess.DEVNULL, check=True)
        common = [args.cargo_kani, "kani", "--lib", "--no-default-features", "--features", "std",
                  "--output-format", "terse", "-Z", "unstable-options", "--harness-timeout", "180s"]
        command = common + ["--manifest-path", str(VENDOR / "Cargo.toml"), "--jobs", str(args.jobs),
                            "--export-json", str(out / "kani.json")]
        print(f"Verifying {len(contracts)} harnesses with Kani {version}; logs: {out}", flush=True)
        rc = execute(command, out / "kani.log", env)
        if digest(VENDOR / "Cargo.lock") != lock_hash:
            raise RuntimeError("Kani changed the pinned dependency lockfile")
        if rc:
            raise RuntimeError(f"Kani exited {rc}; see kani.log and kani.json")
        report, rows = results(out / "kani.json")
        validate_positive(report, rows, contracts)
        controls = {}
        if args.self_test:
            mutations = [
                dict(
                    name="nonce_mutation",
                    harness="kani_proofs::nonce_matches_spark_xor_encoding",
                    file="src/crypto/cipher.rs",
                    old="let mut seq_bytes = [0u8; NONCE_LEN];",
                    new="let mut seq_bytes = [1u8; NONCE_LEN];",
                    occurrences=2,
                    expected_failure="nonce differs from spark",
                ),
                dict(
                    name="receive_counter_mutation",
                    harness="record_layer::kani_proofs::incoming_success_advances_once_and_preserves_plaintext",
                    file="src/record_layer.rs",
                    old="self.read_seq += 1;",
                    new="self.read_seq += 0;",
                    occurrences=1,
                    expected_failure="successful receive advances sequence once",
                ),
                dict(
                    name="inner_type_mutation",
                    harness="kani_proofs::tls13_unpadding_preserves_content_and_extracts_last_nonzero_type",
                    file="src/msgs/message/inbound.rs",
                    old="Some(content_type) => return ContentType::from(content_type),",
                    new="Some(_content_type) => return ContentType::ApplicationData,",
                    occurrences=1,
                    expected_failure="tls inner content type equals the last nonzero byte",
                ),
            ]
            for mutation in mutations:
                controls[mutation["name"]] = mutation_control(common, env, out, **mutation)
            rc = execute(common + ["--manifest-path", str(VENDOR / "Cargo.toml"),
                         "--harness", "kani_proofs::nonce_matches_spark_xor_encoding", "--exact",
                         "--unwind", "1", "--export-json", str(out / "unwind.json")],
                         out / "unwind.log", env)
            controls["insufficient_unwind"] = control_failed_as_expected(out / "unwind.json", rc, "unwind")
            print("All four negative controls failed for their expected reasons.", flush=True)
        verify()
        if digest(VENDOR / "Cargo.lock") != lock_hash:
            raise RuntimeError("A control changed the pinned dependency lockfile")
        if proof_source_hashes() != input_hashes:
            raise RuntimeError("Proof inputs changed during verification")
        summary = {
            "complete": True, "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "seconds": time.monotonic() - started, "tools": report["tools"],
            "target": report["metadata"]["target"], "features": ["std"], "default_features": False,
            "upstream_files_verified": upstream_files, "command": command,
            "source_sha256": input_hashes,
            "controls": controls,
            "contracts": [c | {"status": "verified", "duration_ms": next(r["duration_ms"] for r in rows if r["harness_id"] == c["harness"])} for c in contracts],
        }
        save(out / "summary.json", summary)
        save(out / "status.json", {"complete": True, "verified": len(contracts), "controls": len(controls)})
        print(f"PASS: {len(contracts)} contracts; {len(controls)} negative controls.", flush=True)
    except Exception as error:
        save(out / "status.json", {"complete": False, "error": str(error)})
        raise


if __name__ == "__main__":
    main()
