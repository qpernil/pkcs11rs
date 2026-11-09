# Virtual YubiHSM algorithm benchmarks

`tools/virtual-hsm-benchmark.py` compares RSA, every EC curve exposed by the
full virtual-HSM firmware, ML-DSA, ML-KEM, and all three supported hybrid KEMs.
It runs the same `virtual-yubihsm-core::Device` native command dispatcher used
by the connector, with disposable in-memory factory devices and their factory
authorization snapshots. It never connects to a service, reads a token store,
or discovers physical devices. No authentication password is needed.

Run on macOS or Linux from a checkout with the sibling dependencies available:

```sh
python3 tools/virtual-hsm-benchmark.py --output target/benchmarks/virtual-hsm
```

The runner builds locked `firmware-full` release dependencies and compiles two
small executables against those exact artifacts. One measures latency with the
ordinary allocator. The other profiles Rust heap allocations with a wrapper
around the system allocator. Each algorithm/operation/run has a fresh process.
Results include CSV, per-run JSON, and host/compiler/commit/source-hash metadata.
An output directory must be new; completed rows are saved incrementally.

## Coverage and timing

- RSA-2048/3072/4096: native creation, creation plus public-key retrieval, signing.
- NIST P-224/256/384/521, secp256k1, Brainpool P-256/384/512: creation,
  creation plus public-key retrieval, signing, and ECDH.
- Ed25519/Ed448: creation, creation plus public-key retrieval, signing.
- X25519/X448: creation, creation plus public-key retrieval, key agreement.
- ML-DSA-44/65/87: creation, creation plus public-key retrieval, signing.
- ML-KEM-512/768/1024 and ML-KEM-768+P-256, ML-KEM-768+X25519,
  ML-KEM-1024+P-384: creation, creation plus public-key retrieval,
  encapsulation, decapsulation.

Every signature is verified before timing. ECDH is checked against the peer's
shared secret, and KEM encapsulation/decapsulation must round-trip correctly.
Verification is a correctness check, not a timed native-HSM operation.

The default timing result is the median of three independent run medians.
Each run measures 200 calls after ten warmups. Creation uses three measured
calls per run without warmups; it uses fresh random keys and is inherently
variable, especially for RSA. Memory runs measure three calls separately.
`--runs`, `--samples`, `--keygen-samples`, `--memory-samples`, and
`--algorithms` permit explicitly recorded smaller or larger workloads.

`keygen` times the native command that returns an object ID. `keypair` also
retrieves the new public key within the timer, accounting for public material
that an implementation computes lazily. Key deletion, request construction,
output disposal, correctness checks, and initial device setup are outside the
timer. Native dispatch, authorization, cryptographic work, and response
allocation are inside it. Signing uses SHA-256-size prepared digests for RSA
and most ECDSA curves, SHA-224/384/512-size digests for the corresponding curves,
and raw messages for EdDSA and hedged pure ML-DSA.

These are core-operation measurements. HTTP, secure-session encryption,
persistence, PKCS #11 projections/metadata, and application scheduling are
excluded. ECDH derives one raw shared secret; KEM encapsulation and
decapsulation perform different protocol work. Algorithm names retain their
parameter sizes; rows do not imply identical classical or quantum security.

## Memory and storage

The report separates quantities that cannot be substituted for one another:

- `peak_extra_rust_heap_bytes`: maximum extra live requested Rust allocation
  bytes above the baseline for one operation. It includes the response buffer.
  It excludes stack, allocator overhead, and allocations outside Rust.
- `retained_key_rust_heap_bytes`: marginal live Rust heap growth across the
  first key creation, including bookkeeping or lazy initialization. This is
  not the complete RAM occupied by a key: inline fields and spare capacity
  already reserved by the device's object map are part of the baseline.
- `process_peak_rss_bytes`: fresh-process maximum resident memory from
  `/usr/bin/time`, covering initialization, correctness checks, warmups and
  measured operations, along with code pages, stack and allocator overhead.
  It is not an isolated per-operation stack high-water mark.
- `native_key_bytes` and `native_key_pages`: device-reported object length and
  its 126-byte-page charge. Each key also consumes one object record. Native
  compact seed storage can coexist with much larger expanded keys in RAM.
- `public_bytes`: native public-key response length excluding its algorithm
  byte, not DER/SPKI size. RSA's exponent is implicit, and Weierstrass public
  responses omit the SEC1 prefix. `response_bytes` is the timed command's output.

A low temporary-heap count does not establish a low total working-memory
requirement. In particular, stack-heavy crypto can have small heap deltas.
The heap profiler is compiled separately so its atomic counters do not affect
reported latency. Peak RSS comes from that profiling process and includes the
profiler itself. Memory maxima over three calls are observed values, not bounds.

The current hybrid private keys retain a compact seed and reconstruct their
components during public-key retrieval and use. Their creation-only latency
and marginal retained heap therefore exclude work visible in `keypair`,
encapsulation and decapsulation. These measurements characterize the current
implementation, including such caching and reconstruction choices.

## Recorded measurements

[Apple M5 Pro / macOS ARM64, 2026-11-10](benchmarks/virtual-hsm-macos-20261110/README.md)
contains all 24 algorithms/constructions and 86 cases, including every supported
EC curve and hybrid KEM, with raw results and provenance.
