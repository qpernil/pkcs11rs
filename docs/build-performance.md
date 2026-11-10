# Build performance

## Release compilation

`cargo build --release` builds the workspace's default members, including the
PKCS #11 library, connector, and authoring tool. Dependencies are reused when
their inputs and build configuration match. A change to the main crate still
requires substantial compilation and optimization of that crate.

The workspace uses Cargo's default release profile: optimization level 3,
incremental compilation disabled, and no cross-crate LTO. Local ThinLTO can
optimize across code-generation units within each crate. Inlining can also
bring eligible dependency function bodies into a consuming crate. See
[Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html).

## Protocol extraction measurement

An experiment on 2026-11-10 compared the existing layout with a workspace
subcrate containing the YubiHSM command encoders and response parsers. The
candidate moved 1,395 implementation lines and 598 test lines out of the main
crate. Transport, secure sessions, and PKCS #11 policy remained in pkcs11rs.
The candidate used protocol-specific errors with equivalent PKCS #11 error
mapping in the adapter.

Measurements used an Apple M5 Pro with 48 GB RAM and rustc 1.99.1
(`58cf8f9c3`, aarch64-apple-darwin), RSA 0.9.10, and the Git-pinned ML-DSA
0.1.1. The raw observations identify the measured lockfile by SHA-256. Both
layouts included the same pending
correctness fixes. The command was:

```sh
cargo build --release --locked --offline --timings
```

| Case | Runs per layout | Existing layout | Extracted codec |
| --- | ---: | ---: | ---: |
| Main-crate rebuild, dependencies cached | 5 | 9.00 s median | 9.10 s median |
| Fresh artifact directory, dependency sources cached | 2 | 26.82 s median | 27.57 s median |

For the first case, touching `src/lib.rs` invalidated the main crate without
changing its contents. Existing dependency artifacts were retained, including
the extracted codec in the candidate. Existing-layout observations ranged
from 8.92 to 9.17 seconds; candidate observations ranged from 9.01 to 9.13
seconds.

Each fresh-build run used a different empty `CARGO_TARGET_DIR`. This measures
the compilation work required after `cargo clean` without deleting the normal
development cache. Downloaded sources were available locally, and no builds
ran concurrently with the measured builds. These are build measurements;
test execution is excluded.

The extraction produced no observed improvement and was reverted. The small
sample does not establish a precise regression or predict the result of a
larger extraction. It does show that moving this codec alone is insufficient
to reduce the main crate's recurring build cost. The candidate passed the
all-feature workspace compilation check and all measured release builds;
runtime behavior was not qualified for the discarded candidate.

[Raw observations](benchmarks/protocol-extraction-build-times.json) retain
every run. Further extraction should be justified by useful ownership
boundaries and measured compiler work, rather than source-line count alone.

## Disabling local ThinLTO

Using the original source layout and the same measurement method, the
environment override below disables local ThinLTO while retaining release
optimization level 3 and normal inlining:

```sh
CARGO_PROFILE_RELEASE_LTO=off cargo build --release
```

| Case | Runs per configuration | Default release | Local ThinLTO disabled |
| --- | ---: | ---: | ---: |
| Main-crate rebuild, dependencies cached | 5 | 9.00 s median | 7.74 s median |
| Fresh artifact directory, dependency sources cached | 2 | 26.82 s median | 23.61 s median |

Three follow-up rebuilds with the default settings had a median of 8.86
seconds, consistent with the initial baseline. Main-crate rebuilds with local
ThinLTO disabled were about 13–14% faster than these default baselines. The compiled
library grew from 12,621,536 to 14,083,968 bytes, about 12%, and retained the
same 141 exported symbol names. Identical exports do not establish equivalent
runtime performance. Runtime throughput was not benchmarked, and no persistent
release-profile setting was changed.

[Raw observations](benchmarks/local-thinlto-build-times.json) include every
run and the configuration difference. The first build after changing the
profile can rebuild dependencies; the warm measurements exclude that cache
preparation.
