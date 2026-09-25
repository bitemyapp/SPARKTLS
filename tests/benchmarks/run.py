#!/usr/bin/env python3
"""Repeated, same-client TLS comparisons. See README.md for measurement scope."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RUST = HERE / "rustls"
SUITES = ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
          "TLS_CHACHA20_POLY1305_SHA256")
IMPLEMENTATIONS = ("sparktls", "openssl", "rustls")


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, default=str) + "\n")
    temporary.replace(path)


def execute(command, *, cwd=ROOT, env=None, timeout=60, data=b""):
    command = list(map(str, command))
    start = time.monotonic()
    process = subprocess.run(command, cwd=cwd, env=env, input=data,
                             capture_output=True, timeout=timeout)
    return {"command": command, "cwd": str(cwd), "rc": process.returncode,
            "seconds": time.monotonic() - start,
            "stdout": process.stdout.decode(errors="replace"),
            "stderr": process.stderr.decode(errors="replace")}


def checked(command, **kwargs):
    result = execute(command, **kwargs)
    if result["rc"]:
        raise RuntimeError(f"Command failed: {result}")
    return result


def parse_stime(result, scenario, response_bytes=0):
    """OpenSSL 3.0 can return 1 on success; only a complete run qualifies."""
    output = result["stdout"] + "\n" + result["stderr"]
    real = re.findall(r"(\d+) connections in (\d+) real seconds, (\d+) bytes read per connection", output)
    cpu = re.findall(r"(\d+) connections in [\d.]+s; [\d.]+ connections/user sec, bytes read (\d+)", output)
    if (result["rc"] not in (0, 1) or len(real) != 1 or len(cpu) != 1
            or re.search(r"error|failed|unable", output, re.I)):
        raise RuntimeError("s_time failed or did not produce a complete summary")
    count, rounded_seconds, average_bytes = map(int, real[0])
    cpu_count, total_bytes = map(int, cpu[0])
    marks = "".join(re.findall(r"^([*r]+)$", output, re.M))
    expected_mark = "r" if scenario == "bulk" else "*"
    if (count <= 0 or cpu_count != count or result["seconds"] <= 0
            or marks != expected_mark * count):
        raise RuntimeError("Unexpected handshake count or resumption mode")
    if average_bytes != response_bytes or total_bytes != count * response_bytes:
        raise RuntimeError("Incomplete or unexpected application response")
    return {"connections": count, "openssl_rounded_seconds": rounded_seconds,
            "response_bytes": average_bytes, "total_response_bytes": total_bytes}


def validate_probe(result, suite):
    output = result["stdout"] + result["stderr"]
    if (result["rc"] or "CONNECTION ESTABLISHED" not in output
            or "TLSv1.3" not in output or suite not in output
            or not re.search(r"(?:Temp Key|group): X25519\b", output, re.I)
            or "Verification: OK" not in output
            or "ed25519" not in output.lower()):
        raise RuntimeError("TLS identity, certificate, protocol, cipher or group probe failed")


def validate_http(response, expected_digest, expected_size):
    separator = b"\r\n\r\n" if b"\r\n\r\n" in response else b"\n\n"
    headers, found, body = response.partition(separator)
    if not found or not re.match(rb"HTTP/1\.[01] 200(?: |\r|\n)", headers):
        raise RuntimeError("Expected an HTTP 200 response")
    if len(body) != expected_size or hashlib.sha256(body).hexdigest() != expected_digest:
        raise RuntimeError("Payload length or SHA-256 mismatch")
    return {"response_bytes": len(response), "payload_bytes": len(body),
            "sha256": expected_digest, "headers": headers.decode("ascii")}


def order_for(iteration, names):
    # Rotate first position and alternate direction: all permutations for 3.
    names = list(names)
    shift = iteration % len(names)
    names = names[shift:] + names[:shift]
    return names if (iteration // len(names)) % 2 == 0 else names[::-1]


class Server:
    """Only signal the process group this runner created."""
    def __init__(self, command, cwd, env, log):
        self.log = log.open("wb")
        try:
            self.process = subprocess.Popen(list(map(str, command)), cwd=cwd, env=env,
                                            stdin=subprocess.DEVNULL, stdout=self.log,
                                            stderr=subprocess.STDOUT, start_new_session=True)
        except BaseException:
            self.log.close()
            raise
        self.command = list(map(str, command))

    def close(self):
        try:
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait()
        finally:
            self.log.close()

    def ready(self, port):
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError(f"Server exited: {self.command}; see {self.log.name}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"Server readiness timed out: {self.command}")


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fingerprint(args):
    commands = {"openssl": [args.openssl, "version", "-a"],
                "git": ["git", "rev-parse", "HEAD"],
                "git_status": ["git", "status", "--short"],
                "cpu": ["sysctl", "-n", "machdep.cpu.brand_string"] if sys.platform == "darwin"
                else ["lscpu"]}
    if "rustls" in args.implementations:
        commands.update(rustc=["rustc", "-Vv"], cargo=["cargo", "--version"])
    if "sparktls" in args.implementations:
        commands["alire"] = [args.alr, "--version"]
        commands["gnat"] = [args.alr, "-n", "--no-tty", "exec", "--", "gnatls", "-v"]
        commands["gprbuild"] = [args.alr, "-n", "--no-tty", "exec", "--", "gprbuild", "--version"]
    result = {"platform": platform.platform(), "machine": platform.machine(),
              "python": sys.version, "cpu_count": os.cpu_count(),
              "load_average": os.getloadavg(), "arguments": vars(args),
              "build_environment": {k: v for k, v in os.environ.items()
                                    if k.startswith(("SPARK", "RUSTFLAGS", "CARGO_BUILD_", "CARGO_PROFILE_", "AWS_LC_SYS_"))
                                    or k in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "RUSTC_WRAPPER", "CARGO_ENCODED_RUSTFLAGS")}}
    for name, command in commands.items():
        try:
            result[name] = execute(command)
        except OSError as error:
            result[name] = {"unavailable": str(error)}
    result["dependencies"] = {}
    for name in ("sparkx509", "sparktlscrypto", "sparkmlkem", "sparkentropy", "sparkpiv"):
        path = ROOT.parent / name
        if path.is_dir():
            top = execute(["git", "rev-parse", "--show-toplevel"], cwd=path)
            if top["rc"] == 0 and Path(top["stdout"].strip()).resolve() == path.resolve():
                result["dependencies"][name] = {
                    "revision": execute(["git", "rev-parse", "HEAD"], cwd=path),
                    "status": execute(["git", "status", "--short"], cwd=path)}
            else:
                # A copied dependency may sit inside an unrelated parent Git
                # checkout. Its HEAD does not identify this dependency.
                result["dependencies"][name] = {"source_copy": True, "revision": None}
    return result


def source_hashes(out):
    # Also identify uncommitted adapter/source changes: git HEAD alone cannot.
    paths = list(ROOT.glob("*.gpr")) + list(ROOT.glob("alire.*"))
    for directory in (ROOT / "src", ROOT / "generated", ROOT / "examples", HERE):
        for current, dirs, names in os.walk(directory):
            dirs[:] = sorted(d for d in dirs if d not in ("target", "results", "__pycache__", ".git"))
            for name in sorted(names):
                path = Path(current) / name
                if path.suffix in (".adb", ".ads", ".gpr", ".py", ".rs", ".toml", ".lock"):
                    paths.append(path)
    paths.extend(ROOT / "tests" / name for name in ("benchmark.sh", "bench_bulk.sh", "bench_quick.sh"))
    paths.extend((ROOT / "tests/x509/x509_validate.adb", ROOT / "tests/x509/x509_validate.gpr"))
    for name in ("sparkx509", "sparktlscrypto", "sparkmlkem", "sparkentropy", "sparkpiv"):
        dependency = ROOT.parent / name
        paths.extend(dependency.glob("*.gpr"))
        paths.extend(dependency.glob("alire.*"))
        for directory in (dependency / "src", dependency / "generated", dependency / "config"):
            if directory.is_dir():
                paths.extend(path for path in directory.rglob("*")
                             if path.is_file() and path.suffix in (".adb", ".ads", ".gpr", ".c", ".h"))
    paths.extend(path for path in (ROOT / "config").glob("*") if path.is_file())
    save(out / "source-sha256.json", {os.path.relpath(path, ROOT): hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in sorted(set(paths)) if path.is_file()})


def build(args, out):
    commands = []
    env = os.environ.copy()
    # Override checked-test settings in each relevant dependency, including
    # crypto's scalar/native mode. Record the effective values with the build.
    for prefix in ("SPARKTLS", "SPARKTLSCRYPTO", "SPARKX509", "SPARKMLKEM"):
        env[prefix + "_BUILD_MODE"] = "optimize"
        env[prefix + "_CONTRACTS"] = "disabled"
        env[prefix + "_RUNTIME_CHECKS"] = "disabled"
    env["SPARKTLSCRYPTO_ASM"] = "enabled"
    if not args.no_build:
        if "sparktls" in args.implementations:
            commands.append([args.alr, "-n", "--no-tty", "build", "--", "-s"])
            mains = []
            if "handshake" in args.scenarios:
                mains.append("tls_bench_server.adb")
            if "bulk" in args.scenarios:
                mains.append("tls_web_epoll.adb")
            if mains:
                commands.append([args.alr, "-n", "--no-tty", "exec", "--", "gprbuild", "-s",
                                 "-P", "examples/sparktls_examples.gpr", f"-j{args.jobs}", *mains])
            if "x509" in args.scenarios:
                commands.append([args.alr, "-n", "--no-tty", "exec", "--", "gprbuild", "-s",
                                 "-P", "tests/x509/x509_validate.gpr", f"-j{args.jobs}"])
        if "rustls" in args.implementations:
            commands.append(["cargo", "build", "--release", "--locked", "--jobs", str(args.jobs),
                             "--manifest-path", RUST / "Cargo.toml", "--target-dir", RUST / "target"])
    save(out / "build.json", {"skipped": args.no_build, "commands": commands,
                              "overrides": {k: v for k, v in env.items() if k.startswith("SPARK")}})
    with (out / "build.log").open("wb") as log:
        for command in commands:
            print("Building:", " ".join(map(str, command)), flush=True)
            subprocess.run(list(map(str, command)), cwd=ROOT, env=env, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
    binaries = {"openssl": Path(args.openssl)}
    if "sparktls" in args.implementations:
        if "handshake" in args.scenarios:
            binaries["sparktls-handshake"] = ROOT / "bin/examples/tls_bench_server"
        if "bulk" in args.scenarios:
            binaries["sparktls-bulk"] = ROOT / "bin/examples/tls_web_epoll"
        if "x509" in args.scenarios:
            binaries["sparktls-x509"] = ROOT / "bin/tests/x509_validate"
    if "sparktls-baseline" in args.implementations:
        for scenario, filename in (("handshake", "tls_bench_server"),
                                   ("bulk", "tls_web_epoll"), ("x509", "x509_validate")):
            if scenario in args.scenarios:
                binaries[f"sparktls-baseline-{scenario}"] = args.baseline_dir / filename
    if "rustls" in args.implementations:
        binaries["rustls"] = RUST / "target/release/sparktls-rustls-bench"
        shutil.copyfile(RUST / "Cargo.lock", out / "Cargo.lock")
    for path in binaries.values():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f"Missing executable: {path}")
    save(out / "binaries.json", {name: {"path": path, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                 for name, path in binaries.items()})
    if "rustls" in binaries:
        save(out / "rustls-version.json", checked([binaries["rustls"], "--version"]))
    return binaries


def fixtures(args, out):
    path = out / "fixtures"
    path.mkdir(mode=0o700)
    commands = [
        ["genpkey", "-algorithm", "ED25519", "-out", "ca.key"],
        ["req", "-new", "-x509", "-key", "ca.key", "-out", "ca.crt", "-days", "2",
         "-subj", "/CN=Benchmark CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        ["genpkey", "-algorithm", "ED25519", "-out", "leaf.key"],
        ["req", "-new", "-key", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost"],
        ["x509", "-req", "-in", "leaf.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
         "-out", "leaf.crt", "-days", "2", "-extfile", "leaf.ext"]]
    (path / "leaf.ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n"
                                   "extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n")
    for command in commands:
        checked([args.openssl, *command], cwd=path)
    if "bulk" in args.scenarios:
        # Deterministic nonconstant data; TLS compression is disabled.
        block = bytes(range(256)) * 4096
        with (path / "payload.bin").open("wb") as file:
            remaining = args.size
            while remaining:
                chunk = block[:min(remaining, len(block))]
                file.write(chunk)
                remaining -= len(chunk)
    return path


def prefix(cpu):
    return [] if cpu is None else ["taskset", "-c", str(cpu)]


def record(out, row):
    with (out / "raw.jsonl").open("a") as file:
        file.write(json.dumps(row, default=str) + "\n")


def network(args, out, fixture, binaries, scenario, suite):
    if args.restart_servers:
        # Independent process layouts; startup and verified preflight remain
        # outside the timed sample. Rotate both startup and measurement order.
        for iteration in range(-args.warmups, args.runs):
            trial = out / f"{scenario}-{suite}-process-{iteration}"
            trial.mkdir()
            print(f"Fresh server trial {iteration}/{args.runs - 1}: {scenario} {suite}", flush=True)
            single = argparse.Namespace(**(vars(args) | {
                "runs": 1, "warmups": 0, "restart_servers": False,
                "implementations": order_for(iteration, args.implementations)}))
            network(single, trial, fixture, binaries, scenario, suite)
            for line in (trial / "raw.jsonl").read_text().splitlines():
                record(out, json.loads(line) | {"iteration": iteration, "process_trial": iteration})
        return
    cell = out / f"{scenario}-{suite}"
    cell.mkdir()
    config = cell / "openssl.cnf"
    config.write_text("openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\n"
                      "system_default = defaults\n[defaults]\nGroups = X25519\n"
                      f"Ciphersuites = {suite}\nMinProtocol = TLSv1.3\nMaxProtocol = TLSv1.3\n")
    env = os.environ | {"OPENSSL_CONF": str(config), "LC_ALL": "C"}
    cert, key = fixture / "leaf.crt", fixture / "leaf.key"
    bulk = scenario == "bulk"
    digest = hashlib.sha256((fixture / "payload.bin").read_bytes()).hexdigest() if bulk else None
    with ExitStack() as stack:
        servers = {}
        for name in args.implementations:
            port = unused_port()
            if name in ("sparktls", "sparktls-baseline"):
                command = [binaries[f"{name}-{scenario}"], cert, key,
                           fixture if bulk else str(port)]
            elif name == "rustls":
                command = [binaries[name], "serve", cert, key, str(port), suite]
                if bulk:
                    command.append(fixture / "payload.bin")
            else:
                command = [args.openssl, "s_server", "-cert", cert, "-key", key,
                           "-accept", f"127.0.0.1:{port}", "-tls1_3", "-groups", "X25519",
                           "-ciphersuites", suite, "-quiet"] + (["-WWW"] if bulk else [])
            server = Server(prefix(args.server_cpu) + command, fixture,
                            env | {"SPARKTLS_PORT": str(port)}, cell / f"{name}-server.log")
            stack.callback(server.close)
            server.ready(port)
            client = prefix(args.client_cpu) + [args.openssl, "s_client", "-connect", f"127.0.0.1:{port}",
                      "-servername", "localhost", "-verify_hostname", "localhost", "-verify_return_error",
                      "-CAfile", fixture / "ca.crt", "-tls1_3", "-groups", "X25519", "-ciphersuites", suite]
            probe = execute(client + ["-brief"], env=env)
            save(cell / f"{name}-probe.json", probe)
            validate_probe(probe, suite)
            response_bytes = 0
            if bulk:
                # Keep the binary response out of JSON; save its checked digest.
                response = subprocess.run(list(map(str, client + ["-quiet", "-ign_eof"])),
                                          input=b"GET /payload.bin HTTP/1.0\r\nHost: localhost\r\n\r\n",
                                          capture_output=True, env=env, timeout=60)
                if response.returncode:
                    raise RuntimeError(f"Payload probe failed: {response.stderr.decode(errors='replace')}")
                info = validate_http(response.stdout, digest, args.size)
                save(cell / f"{name}-payload.json", info)
                response_bytes = info["response_bytes"]
            servers[name] = server, port, response_bytes
        for iteration in range(-args.warmups, args.runs):
            for name in order_for(iteration, args.implementations):
                server, port, response_bytes = servers[name]
                command = prefix(args.client_cpu) + [args.openssl, "s_time", "-connect", f"127.0.0.1:{port}",
                           "-tls1_3", "-ciphersuites", suite, "-CAfile", fixture / "ca.crt",
                           "-verify", "3", "-reuse" if bulk else "-new", "-time", str(args.seconds)]
                if bulk:
                    command += ["-www", "/payload.bin"]
                result = execute(command, env=env, timeout=args.seconds + 60)
                row = result | {"implementation": name, "scenario": scenario, "suite": suite,
                                "iteration": iteration, "timestamp_unix": time.time(),
                                "load_average": os.getloadavg(), "server_command": server.command,
                                "server_pid": server.process.pid}
                try:
                    row.update(parse_stime(result, scenario, response_bytes))
                    if server.process.poll() is not None:
                        raise RuntimeError("Server exited during measurement")
                    row["rate"] = row["connections"] / row["seconds"] * (args.size / 2**20 if bulk else 1)
                except RuntimeError as error:
                    record(out, row | {"error": str(error)})
                    raise
                record(out, row)
                print(f"{scenario} {suite} {iteration:3} {name:8} {row['rate']:.2f} "
                      f"{'MiB/s' if bulk else 'connections/s'}", flush=True)


def validation(args, out, fixture, binaries):
    def command(name, count, hostname="localhost"):
        if name in ("sparktls", "sparktls-baseline"):
            cmd = [binaries[f"{name}-x509"], "leaf.crt", "ca.crt", "--hostname", hostname, "--repeat", str(count)]
        elif name == "rustls":
            cmd = [binaries[name], "verify", "leaf.crt", "ca.crt", hostname, str(count)]
        else:
            # Short relative paths also fit macOS's smaller argv limit.
            cmd = [args.openssl, "verify", "-purpose", "sslserver", "-verify_hostname", hostname,
                   "-CAfile", "ca.crt"] + ["leaf.crt"] * count
        return prefix(args.client_cpu) + cmd
    for name in args.implementations:
        good = execute(command(name, 1), cwd=fixture)
        bad = execute(command(name, 1, "wrong.invalid"), cwd=fixture)
        save(out / f"x509-{name}-probe.json", {"valid": good, "wrong_hostname": bad})
        if good["rc"] != 0 or bad["rc"] != (2 if name == "openssl" else 1):
            raise RuntimeError(f"{name} certificate validation controls failed")
    for iteration in range(-args.warmups, args.runs):
        for name in order_for(iteration, args.implementations):
            result = execute(command(name, args.x509_iters), cwd=fixture, timeout=300)
            row = result | {"implementation": name, "scenario": "x509", "suite": None,
                            "iteration": iteration, "validations": args.x509_iters,
                            "timestamp_unix": time.time(), "load_average": os.getloadavg()}
            if result["rc"]:
                record(out, row | {"error": "certificate validation failed"})
                raise RuntimeError(f"{name} validation failed")
            row["rate"] = args.x509_iters / result["seconds"]
            record(out, row)
            print(f"x509 {iteration:3} {name:8} {row['rate']:.2f} validations/s", flush=True)


def summarize(out):
    rows = [json.loads(line) for line in (out / "raw.jsonl").read_text().splitlines()]
    groups = {}
    for row in rows:
        if row["iteration"] >= 0:
            groups.setdefault((row["scenario"], row["suite"], row["implementation"]), []).append(row["rate"])
    summary = []
    for (scenario, suite, name), rates in groups.items():
        cv = statistics.stdev(rates) / statistics.mean(rates) if len(rates) > 1 else None
        baseline = groups.get((scenario, suite, "openssl"))
        summary.append({"scenario": scenario, "suite": suite, "implementation": name,
                        "runs": len(rates), "median": statistics.median(rates),
                        "min": min(rates), "max": max(rates), "cv": cv,
                        "ratio_to_openssl_medians": statistics.median(rates) / statistics.median(baseline) if baseline else None,
                        "quality": "exploratory" if len(rates) < 20 else
                        "noisy" if cv > 0.05 else "repeatable"})
    save(out / "summary.json", summary)
    print("\nMedians (bulk: payload MiB/s; handshake: connections/s; x509: validations/s)")
    for row in summary:
        ratio = row["ratio_to_openssl_medians"]
        print(f"{row['scenario']:9} {row['suite'] or '-':32} {row['implementation']:8} "
              f"{row['median']:10.2f} {f'{ratio:.3f}x OpenSSL' if ratio is not None else ''} [{row['quality']}]")


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--implementations", nargs="+", choices=(*IMPLEMENTATIONS, "sparktls-baseline"), default=list(IMPLEMENTATIONS))
    parser.add_argument("--scenarios", nargs="+", choices=("handshake", "bulk", "x509"), default=["handshake", "bulk", "x509"])
    parser.add_argument("--suites", nargs="+", choices=SUITES, default=list(SUITES))
    parser.add_argument("--runs", type=positive, default=20)
    parser.add_argument("--warmups", type=positive, default=1)
    parser.add_argument("--seconds", type=positive, default=2)
    parser.add_argument("--size", type=positive, default=16 * 1024 * 1024)
    parser.add_argument("--x509-iters", type=positive, default=int(os.environ.get("X509_ITERS", "5000")))
    parser.add_argument("--restart-servers", action=argparse.BooleanOptionalAction, default=True,
                        help="use fresh server processes for each sample (default: enabled)")
    parser.add_argument("--baseline-dir", type=Path,
                        help="directory of preserved SPARKTLS executables for sparktls-baseline")
    parser.add_argument("--no-build", action="store_true", default=os.environ.get("BENCH_NO_REBUILD") == "1")
    parser.add_argument("--jobs", type=positive, default=min(16, os.cpu_count() or 1))
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--alr", default="alr")
    parser.add_argument("--server-cpu", type=int)
    parser.add_argument("--client-cpu", type=int)
    parser.add_argument("--out", type=Path, help="new directory (default: unique directory under benchmarks/results)")
    args = parser.parse_args()
    if "sparktls-baseline" in args.implementations and args.baseline_dir is None:
        parser.error("sparktls-baseline requires --baseline-dir")
    if args.baseline_dir:
        args.baseline_dir = args.baseline_dir.resolve()
    for attribute in ("implementations", "scenarios", "suites"):
        if len(set(getattr(args, attribute))) != len(getattr(args, attribute)):
            parser.error(f"duplicate {attribute}")
    if args.x509_iters < 1 or args.size > 256 * 1024 * 1024:
        parser.error("x509 iterations must be positive; payload cannot exceed 256 MiB")
    if args.server_cpu is not None or args.client_cpu is not None:
        if sys.platform != "linux" or not shutil.which("taskset"):
            parser.error("CPU affinity requires Linux taskset")
        for cpu in (args.server_cpu, args.client_cpu):
            if cpu is not None and cpu not in os.sched_getaffinity(0):
                parser.error(f"CPU {cpu} is not available to this process")
        if args.server_cpu == args.client_cpu:
            parser.error("server and client must use different CPUs")
    args.openssl = shutil.which(args.openssl)
    if not args.openssl:
        parser.error("OpenSSL executable not found (OpenSSL 3.x required)")
    args.openssl = str(Path(args.openssl).resolve())
    if os.sep in args.alr:
        args.alr = str(Path(args.alr).resolve())
    if args.out:
        args.out = args.out.resolve()
        args.out.mkdir(parents=True, mode=0o700)  # Never overwrite a prior result.
    else:
        (HERE / "results").mkdir(exist_ok=True)
        args.out = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-"), dir=HERE / "results"))
    out = args.out
    print(f"Results: {out}", flush=True)
    save(out / "status.json", {"complete": False})
    try:
        save(out / "fingerprint.json", fingerprint(args))
        if not checked([args.openssl, "version"])["stdout"].startswith("OpenSSL 3."):
            raise RuntimeError("This runner requires OpenSSL 3.x, including when measuring rustls")
        binaries = build(args, out)
        source_hashes(out)
        fixture = fixtures(args, out)
        for scenario in args.scenarios:
            if scenario == "x509":
                validation(args, out, fixture, binaries)
            else:
                for suite in args.suites:
                    network(args, out, fixture, binaries, scenario, suite)
        summarize(out)
        save(out / "status.json", {"complete": True})
    except (Exception, KeyboardInterrupt) as error:
        save(out / "status.json", {"complete": False, "error": str(error) or "interrupted"})
        print(f"Benchmark failed: {error}\nPartial results and build log: {out}", file=sys.stderr)
        return 1
    print(f"Full results: {out}")
    return 0


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
