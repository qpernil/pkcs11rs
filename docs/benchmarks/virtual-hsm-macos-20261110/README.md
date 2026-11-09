# Virtual YubiHSM comparison on Apple M5 Pro

Measured on 2026-11-10, macOS ARM64, Apple M5 Pro, locked release
`firmware-full` virtual-HSM core. These are disposable in-memory native command
measurements; no lab service or physical HSM was accessed.

[Method and reproduction](../../virtual-hsm-benchmarks.md) describes the scope,
sample counts, encoding differences, and memory limitations. The full data cover
**24 algorithms/constructions and 86 operation cases**. Each timing entry is the
median of three independent run medians: 200 calls per run for operations and
three calls per run for creation. Memory uses three separately instrumented calls.

- [CSV](summary.csv): every operation's timing, memory and size fields.
- [Summary JSON](summary.json): includes individual run medians.
- [Raw run results](raw.json): timing percentiles and the separate memory run.
- [Provenance](metadata.json): CPU, compiler, dependency revisions and source hashes.

## Interpretation

ML-KEM-768 encapsulation and decapsulation take about 15 µs apiece, versus
18 µs for X25519 and 90 µs for P-256 ECDH. These perform different protocol
work; the numbers describe the implementation rather than equivalent complete
handshakes. ML-DSA-44 signing takes about 96 µs: slower than P-256 (60 µs) and
Ed25519 (7 µs), faster than P-384 (173 µs) and RSA-3072 (2,181 µs). The
parameter sets represent different security levels.

Standalone ML-DSA retains substantial expanded-key heap: approximately 64,
106 and 174 KiB for ML-DSA-44/65/87. The hybrid KEM implementation retains a
compact seed and reconstructs components during public retrieval and operations;
this reduces retained heap growth while adding work to encapsulation and
decapsulation. Its fast ID-only creation is not full key-pair computation.

Temporary Rust heap is **not total algorithm RAM**. Stack allocations, inline
fields and already-reserved object-map capacity are not in a marginal heap
delta. Whole-process peak RSS includes initialization, warmups, code and the
memory profiler; it cannot be treated as per-operation stack usage. All these
RSS values are for the benchmark executable, not the complete HTTP connector.
The process baselines dominate these small per-key workloads.

## Signing

RSA and ECDSA sign prepared digests; EdDSA and ML-DSA sign messages.
Heap values include response allocation. Each signature passes verification
before timing; host verification itself is not timed.

| Algorithm | Sign µs | Temporary Rust heap KiB | Process peak RSS MiB |
| --- | ---: | ---: | ---: |
| RSA-2048 | 754.96 | 11.698 | 3.30 |
| RSA-3072 | 2,180.79 | 22.323 | 3.39 |
| RSA-4096 | 4,916.58 | 22.698 | 3.39 |
| P-224 | 144.33 | 0.116 | 2.98 |
| P-256 | 59.92 | 0.132 | 2.95 |
| P-384 | 172.83 | 0.194 | 3.00 |
| P-521 | 421.79 | 0.264 | 2.95 |
| secp256k1 | 45.54 | 0.131 | 2.91 |
| Brainpool-P256 | 234.83 | 0.132 | 2.97 |
| Brainpool-P384 | 612.21 | 0.194 | 2.98 |
| Brainpool-P512 | 1,575.08 | 0.258 | 3.19 |
| Ed25519 | 7.29 | 0.062 | 2.66 |
| Ed448 | 231.21 | 0.111 | 2.64 |
| ML-DSA-44 | 95.88 | 7.363 | 3.16 |
| ML-DSA-65 | 171.08 | 9.731 | 3.38 |
| ML-DSA-87 | 186.12 | 13.519 | 3.48 |

## Agreement and KEMs

ECDH computes a raw shared secret. KEM encapsulation returns ciphertext plus a
32-byte secret; decapsulation returns the secret. Round-trip checks precede timing.

| Algorithm | ECDH / decap µs | Encap µs | ECDH / decap temporary heap KiB | Encap temporary heap KiB | ECDH / decap peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| P-224 | 68.58 | — | 0.055 | — | 2.80 |
| P-256 | 89.71 | — | 0.062 | — | 2.78 |
| P-384 | 305.50 | — | 0.094 | — | 2.86 |
| P-521 | 205.75 | — | 0.129 | — | 2.77 |
| secp256k1 | 20.29 | — | 0.062 | — | 2.69 |
| Brainpool-P256 | 113.38 | — | 0.062 | — | 2.80 |
| Brainpool-P384 | 308.46 | — | 0.094 | — | 2.80 |
| Brainpool-P512 | 774.21 | — | 0.125 | — | 2.78 |
| X25519 | 17.79 | — | 0.062 | — | 2.66 |
| X448 | 210.50 | — | 0.109 | — | 2.70 |
| ML-KEM-512 | 8.79 | 9.04 | 0.062 | 2.594 | 2.94 |
| ML-KEM-768 | 14.88 | 14.83 | 0.062 | 3.781 | 2.94 |
| ML-KEM-1024 | 23.08 | 22.58 | 0.062 | 5.125 | 2.98 |
| ML-KEM-768+P-256 | 145.79 | 174.83 | 3.423 | 5.548 | 3.22 |
| ML-KEM-768+X25519 | 52.42 | 59.25 | 3.297 | 5.516 | 3.06 |
| ML-KEM-1024+P-384 | 432.88 | 536.50 | 4.376 | 7.329 | 3.28 |

## Creation and storage

ID-only creation can defer public-key computation. Full pair creation here means
native creation followed by public-key retrieval inside the timer. Each creation
sample uses a fresh random key, so RSA medians are especially variable: subtracting
the two independently sampled columns does not isolate public-key retrieval cost.
Native bytes/pages are device storage charges, not expanded key RAM. All entries
consume one device object record; no PKCS #11 companions are created by this test.

| Algorithm | ID-only create µs | Create + public µs | Marginal retained heap growth KiB | Full pair temporary heap KiB | Native bytes | Pages |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RSA-2048 | 87,603.25 | 121,942.46 | 1.598 | 14.871 | 896 | 8 |
| RSA-3072 | 388,082.92 | 274,419.42 | 2.598 | 28.121 | 1344 | 11 |
| RSA-4096 | 1,289,394.67 | 1,187,276.67 | 2.723 | 28.746 | 1792 | 15 |
| P-224 | 1.21 | 69.96 | 0.020 | 0.131 | 84 | 1 |
| P-256 | 1.17 | 29.50 | 0.020 | 0.146 | 96 | 1 |
| P-384 | 1.17 | 89.71 | 0.020 | 0.209 | 144 | 2 |
| P-521 | 92.79 | 248.88 | 0.020 | 0.279 | 198 | 2 |
| secp256k1 | 1.17 | 21.71 | 0.020 | 0.146 | 96 | 1 |
| Brainpool-P256 | 1.21 | 115.88 | 0.020 | 0.146 | 96 | 1 |
| Brainpool-P384 | 1.54 | 300.33 | 0.020 | 0.209 | 144 | 2 |
| Brainpool-P512 | 2.17 | 781.67 | 0.020 | 0.271 | 192 | 2 |
| Ed25519 | 8.38 | 8.33 | 0.254 | 0.317 | 128 | 2 |
| Ed448 | 226.33 | 227.88 | 0.488 | 0.601 | 228 | 2 |
| ML-DSA-44 | 44.38 | 45.08 | 64.395 | 66.958 | 32 | 1 |
| ML-DSA-65 | 84.12 | 84.21 | 106.426 | 110.239 | 32 | 1 |
| ML-DSA-87 | 114.08 | 115.25 | 174.457 | 179.521 | 32 | 1 |
| X25519 | 1.21 | 8.38 | 0.020 | 0.083 | 64 | 1 |
| X448 | 1.21 | 212.67 | 0.020 | 0.130 | 112 | 1 |
| ML-KEM-512 | 9.42 | 9.54 | 2.191 | 3.755 | 64 | 1 |
| ML-KEM-768 | 16.42 | 16.62 | 3.191 | 5.505 | 64 | 1 |
| ML-KEM-1024 | 25.88 | 26.71 | 4.191 | 7.255 | 64 | 1 |
| ML-KEM-768+P-256 | 1.12 | 46.38 | 0.066 | 5.615 | 32 | 1 |
| ML-KEM-768+X25519 | 1.08 | 25.33 | 0.066 | 5.583 | 32 | 1 |
| ML-KEM-1024+P-384 | 1.12 | 116.54 | 0.066 | 7.396 | 32 | 1 |
