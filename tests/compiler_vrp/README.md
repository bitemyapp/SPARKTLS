# GCC array-slice wrong-code reproducer and RFC patch

The compiler incorrectly bounds a four-byte slice as a one-byte access when
using its starting index's value range. In the reproducer, this tells IPA
modref that eight stores cover 29 bytes when they actually cover 32. The caller
then reuses stale values for the final three bytes.

## Reproduce

Only GNAT is required. This is a 44-line standalone Ada program; it does not
depend on SPARKTLS or SPARKNaCl.

```sh
gnatmake -f -O2 -gnatp array_slice_extent.adb
./array_slice_extent
```

Unpatched GNAT 16.1.0 exits with PROGRAM_ERROR. The correct result is exit 0.
The same failure occurs at O3. This control passes:

```sh
gnatmake -f -O2 -gnatp -fno-tree-vrp array_slice_extent.adb
./array_slice_extent
```

The patched compiler passes with VRP enabled. A simpler constant-block copy
did not reproduce the defect; the returned-array serialization shape in this
test is intentional.

## Upstream packet

- [BUG_REPORT.md](BUG_REPORT.md): diagnosis, expected behavior, reproduction,
  and targeted validation.
- [SUBMISSION.txt](SUBMISSION.txt): draft RFC message with ChangeLog entries.
- [Mainline patch](gcc-mainline-array-slice-extent.patch): source fix plus
  gnat.dg regression test. Base is recorded in mainline-reference.json.
- [GCC 16.1 patch](gcc-16-array-slice-extent.patch): tested backport, including
  the same regression test.
- [toolchain.txt](toolchain.txt): exact compiler and source/build configuration.

Apply the appropriate patch from its GCC checkout root using `git apply`.
Both patches passed `git apply --check` against their pristine source versions.
The mainline patch passed GCC's check_GNU_style.sh.

This is a bug-report/RFC packet. The GCC 16.1 backport was built and tested;
the mainline patch was source-inspected and apply-checked. A complete bootstrap
and the broader testsuites required for a middle-end change have not been run.
See [GCC's testing requirements](https://gcc.gnu.org/contribute.html#testing).
No upstream bug report, email, or pull request has been sent from this task.
No patched compiler binary is vendored or installed by this packet.

## Digest validation

hash_probe.adb checks 5,500 messages through both SHA-256 and SHA-512. Build
it in a fresh directory for each compiler/flag variant, using a source-only
copy of SPARKNaCl 4.0.1. With that path in SPARKNACL_SRC, an installed-compiler
control is:

```sh
mkdir control
cd control
gnatmake -f -I"$SPARKNACL_SRC" ../hash_probe.adb -cargs -O2 -gnatp -gnatn -fPIE -fno-tree-vrp
./hash_probe > hashes.txt
python3 ../verify_hashes.py hashes.txt
```

For a patched frontend selected with `-B/path/to/frontends/`, remove
`-fno-tree-vrp` and explicitly select its matching runtime using GNAT's
`--RTS` option. The experiment retained the installed GNAT 16.1 runtime and
passed `-fPIE` to both source-built compiler variants.

The digest oracle uses Python hashlib and reproduces all input bytes
independently. No timed run uses the incorrect stock/VRP-enabled SHA-256 code.

## Measurements and evidence

[Investigation report](../benchmarks/PERFORMANCE_COMPILER_2026-09-25.md)
contains the primitive and TLS results and their limitations. The evidence
directory includes process-level microbenchmarks, compact network trials,
paired bootstrap analysis, hashes, and correctness summaries. Running
`python3 evidence/analyze_network.py` regenerates the network analysis.

Full build logs, dumps, raw client output, and experimental binaries remain on
wx-workstation in `/home/callen/work/sparktls-perf-2026-09-24/compiler-vrp-2026-09-25`.
The GCC checkout there is a local experimental branch, outside SPARKTLS.
