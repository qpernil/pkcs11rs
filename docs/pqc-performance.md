# Software post-quantum performance measurements

`tools/pqc-benchmark.py` measures all three ML-DSA and all three ML-KEM
parameter sets at two layers: `software-key-core` and the public PKCS #11
software-slot interface. It supports macOS and Linux and requires Python 3.11
or newer, Cargo, and rustc.

```sh
python3 tools/pqc-benchmark.py --offline --output /tmp/pkcs11rs-pqc-results
```

The output directory must not exist. Omit `--offline` when dependencies need
to be downloaded. The runner builds the locked release dependencies with
native hardware support disabled, then compiles the Rust timing harness
against those exact artifacts. This build uses the repository's release
target directory and replaces its PKCS #11 library with the software-only
build; run the ordinary release build afterward when a native-hardware
library is needed.

The benchmark process receives a clean environment with one ephemeral named
software slot and hardware discovery disabled. It has no persistent token
store or remote connector configuration. It creates only in-memory test keys
and uses a synthetic ephemeral login gate; it does not authenticate to any
device or existing token.

Each operation has 100 warmup calls followed by 2,000 timed calls per run.
The default is two sequential runs on one thread. ML-DSA signs 32-byte
messages with an empty context and hedge-preferred randomness. Private keys
retain their normal expanded state. Verification and encapsulation use the
shared API's public-key decoding path.

PKCS #11 signing and verification include their `Init` calls. Signing and
encapsulation include output-length queries. KEM operations include creation
of the resulting session-secret object. Output disposal, key destruction,
and session-object cleanup happen outside the timed interval. Login,
persistent storage, network, USB, and device operation latency are excluded.

The harness checks valid signatures and matching KEM secrets for every
parameter set at both layers, plus modified-message rejection in the core.
An unsuccessful check stops the run. Raw CSV files record the mean, median,
95th percentile, and throughput of each operation. `summary.json` combines
the equally sized runs' means and retains each run's timing statistics;
`metadata.json` records source revisions, dependency versions, compiler,
machine information, and build commands.

ML-DSA's rejection sampling produces variable signing times. Use the mean
for average throughput and the recorded percentiles for latency; a single
signature is not a representative performance measurement. Cross-machine
comparisons also depend on compiler version, CPU scheduling, clock speed,
thermal state, and background load. These measurements do not estimate TDX
overhead or hardware-token performance.
