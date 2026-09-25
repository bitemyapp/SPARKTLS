#!/usr/bin/env python3
"""Check the pinned crate, permitting only the documented proof-only additions."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / "third_party/rustls"
MANIFEST = ROOT / "third_party/rustls-upstream-sha256.json"
ADDED = {
    "src/kani_proofs.rs",
    "src/msgs/fragmenter/kani_proofs.rs",
    "src/record_layer/kani_proofs.rs",
}
SUFFIXES = {
    "src/lib.rs": "\n// Local SPARKTLS contract transfer; absent from normal builds.\n#[cfg(kani)]\nmod kani_proofs;\n",
    "src/msgs/fragmenter.rs": "\n// Local contract harnesses need private state to establish the invariant.\n#[cfg(kani)]\nmod kani_proofs;\n",
    "src/record_layer.rs": "\n// Local contract harnesses need private state to establish the invariant.\n#[cfg(kani)]\nmod kani_proofs;\n",
}


def verify():
    manifest = json.loads(MANIFEST.read_text())
    for name, expected in manifest.items():
        data = (VENDOR / name).read_bytes()
        if name in SUFFIXES:
            suffix = SUFFIXES[name].encode()
            if not data.endswith(suffix):
                raise RuntimeError(f"Missing proof-only module declaration: {name}")
            data = data[:-len(suffix)]
        elif name == "Cargo.toml":
            addition = b'    "cfg(kani)",\n'
            if data.count(addition) != 1:
                raise RuntimeError("Missing/duplicated cfg(kani) lint declaration")
            data = data.replace(addition, b"")
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"Undocumented upstream source change: {name}")
    actual = {str(p.relative_to(VENDOR)) for p in VENDOR.rglob("*")
              if p.is_file() and "target" not in p.relative_to(VENDOR).parts}
    if actual != set(manifest) | ADDED:
        raise RuntimeError(f"Unexpected/missing vendor files: {actual ^ (set(manifest) | ADDED)}")
    return len(manifest)


if __name__ == "__main__":
    print(f"Verified {verify()} upstream files; production Rust code unchanged.")
