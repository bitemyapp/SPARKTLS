# Wrong-code: ARRAY_RANGE_REF write extent truncated to one element with VRP

## Summary

On x86_64-pc-linux-gnu, GCC 16.1.0 with `-O2 -gnatp` or `-O3 -gnatp`
miscompiles a fixed-length Ada array slice assignment inside a loop.
The reduced program stores 32 bytes through eight four-byte slices. The
compiler concludes that the callee may write only the first 29 bytes, and
reuses the initial values of bytes 29..31 in the caller.

This produces incorrect SPARKNaCl SHA-256 digests. The arithmetic compression
rounds are not the source of the observed failure: the final output copy
substitutes the last three initial-state bytes (`e0cd19`) for the computed bytes.
For `abc`, the expected ending is `0015ad`; the incorrect digest ends `e0cd19`.

## Reproduction

The attached `array_slice_extent.adb` is standalone Ada and needs no SPARKNaCl,
SPARKTLS, OpenSSL, project file, custom runtime, or third-party Ada library.

With GNAT 16.1.0 on x86-64 Linux:

```sh
gnatmake -f -O2 -gnatp array_slice_extent.adb
./array_slice_extent
```

Expected: normal exit (status 0). Actual: explicit `PROGRAM_ERROR` (status 1)
because the compiler constant-folds a check using stale pre-call values.
The stores themselves execute; observing the array through another call can
show the correct bytes while the optimized local check still fails.

`-O1`, `-fno-tree-vrp`, and `-fno-ipa-modref` avoid the failure. The original
SHA-256 probe also passes with runtime/contract checks enabled. None of those
workarounds is part of the proposed fix.

## Diagnosis

`get_ref_base_and_extent` in `gcc/tree-dfa.cc` handles `ARRAY_REF` and
`ARRAY_RANGE_REF` together. The range-based upper-extent refinement computes
`(maximum_index - lower_bound + 1) * element_size * BITS_PER_UNIT`.

That formula describes an individual element. For an array slice, the known
index is its **starting** index and the access can extend past that element.
Here the starting byte index ranges from 0 to 28 and each slice contains four
bytes. The formula gives 232 bits (29 bytes); the actual union of writes is
256 bits (32 bytes). IPA modref records the incorrect extent and subsequent
optimization treats the final three bytes as unchanged.

The patch restricts this single-element upper-extent refinement to ARRAY_REF.
ARRAY_RANGE_REF retains the existing conservative extent. Range information
can still refine its lower offset. VRP and normal scalar-array optimizations
remain enabled. No Ada language semantics, hash implementation, RNG behavior,
or floating-point behavior changes.

The inspected GCC master also contains the problematic single-element formula.
Its newer nonzero-low-bound handling is a separate change; the supplied mainline
patch preserves it.

## Validation

A stock GCC 16.1.0 source build and a build with this patch use the same
configuration and bootstrap compiler. Both use the installed GNAT 16.1 Ada
runtime, and all comparison binaries explicitly use `-fPIE`.

- Reduced test: unpatched fails at O2 and O3, passes at O1; patched passes all.
- SPARKNaCl SHA-256/SHA-512: 5,500 messages / 11,000 digests per configuration,
  checked against Python hashlib. All 5,500 SHA-256 results fail on stock O2;
  all SHA-512 results pass. Patched O2, patched O3, patched checked O2, and
  stock O2 with the workaround each pass every digest comparison.
- Message lengths 0..257 and 17 larger boundary lengths through 65,536; lower
  bounds 0, 1, 17, 4096, and 2,147,400,000; zero, FF, incrementing, and
  deterministic xorshift patterns.
- The complete upstream SPARKNaCl testall output matches its checked-in golden
  output with patched GCC at O3 and VRP enabled.
- Existing GCC tests ssa-dse-35.c, pr113831.c, and pr113898.c pass the selected
  compile/run checks at O2 and O3 with stock and patched compilers.
  ssa-dse-35 still reports exactly one deleted dead store in both compilers,
  demonstrating that the original ordinary-array optimization is retained.
- This is targeted validation, not a complete GCC bootstrap or testsuite run.

## Relationship to the existing workaround

SPARKNaCl issue #37 identified VRP as the trigger, and PR #38 added
`-fno-tree-vrp`. SPARKTLS PR #18 propagates the workaround to other projects.
This report supplies a dependency-free reproducer and a middle-end diagnosis.

- https://github.com/rod-chapman/SPARKNaCl/issues/37
- https://github.com/rod-chapman/SPARKNaCl/pull/38
- https://github.com/docandrew/SPARKTLS/pull/18

Performance results and exact toolchain/source identities are in the companion
investigation report. They do not compare against a fast but incorrect binary.

This is a bug-report/RFC packet. GCC's contribution guide requires a full
bootstrap and complete testsuites for a middle-end change before merge.
That broader qualification has not been performed in this investigation.
See https://gcc.gnu.org/contribute.html#testing .
