# OASIS PKCS #11 3.2 profile tests

This directory contains a repository-maintained executor for the four final
OASIS PKCS #11 3.2 mandatory provider profile XML artifacts:

- `BL-M-1-32` — Baseline Provider
- `EXT-M-1-32` — Extended Provider
- `AUTH-M-1-32` — Authentication Token
- `CERT-M-1-32` — Public Certificates Token

The exact published XML bytes are embedded in `oasis_cases.py`. The executor
checks each artifact's SHA-256 digest before parsing it, works offline, and
writes a separate result for every case.

## Run the cases separately

Each OASIS artifact is a distinct `unittest` case:

```sh
python3 -m unittest \
  conformance.test_oasis.OasisProfileTests.test_BL_M_1_32 -v
python3 -m unittest \
  conformance.test_oasis.OasisProfileTests.test_EXT_M_1_32 -v
python3 -m unittest \
  conformance.test_oasis.OasisProfileTests.test_AUTH_M_1_32 -v
python3 -m unittest \
  conformance.test_oasis.OasisProfileTests.test_CERT_M_1_32 -v
```

The convenience runner selects one or more cases by their OASIS names:

```sh
python3 conformance/run_oasis.py \
  --case BL-M-1-32 \
  --results target/oasis-results
python3 conformance/run_oasis.py \
  --case CERT-M-1-32 \
  --results target/oasis-results
```

Omit `--case` to execute all four. Without `--module`, the runner builds and
uses the deterministic `abi-tests` backend. This is the mode used in CI to
exercise the executor and prevent regressions.

## Qualify a production module and token

Build the shared library and select the module and slot explicitly:

```sh
cargo build --release --locked
export PKCS11RS_OASIS_PIN='the-user-pin'
python3 conformance/run_oasis.py \
  --module target/release/libpkcs11rs.so \
  --slot 0x1234 \
  --results target/oasis-live-results
```

Use `libpkcs11rs.dylib` on macOS or `pkcs11rs.dll` on Windows. Configure the
normal backend discovery and credentials before launching the runner. Keep
secrets in the environment or the backend's credential source; result files do
not include the PIN.

The selected token must be provisioned for the cases being claimed:

- `BL-M-1-32` and `EXT-M-1-32` require the mechanisms and flags named by their
  XML artifacts.
- `AUTH-M-1-32` requires an RSA-2048 public/private pair labelled
  `testrsa-pub` and `testrsa-pri`, a usable user PIN, and
  `CKM_SHA256_RSA_PKCS` signing. Provisioning owns `CKA_ID`; the certificate
  and key objects that form one identity must receive the same value.
- `CERT-M-1-32` requires the Public Certificates Token profile and a readable
  certificate object. The published vector also reads the label
  `Mozilla Builtin Roots`; provision that label when literal vector matching is
  required.
- A YubiHSM discovery authentication key needs capabilities and domains that
  allow the module to enumerate the qualification objects and read the
  certificate opaque object.

Run only the profile or profiles the deployment intends to claim. A profile
failure is not hidden by success in another case.

## Interpretation and evidence

The XML artifacts contain illustrative provider handles, object ordering,
certificate bytes, key material, and signature bytes. The executor preserves
the specified call sequence and return-value checks while applying these
provider-independent bindings:

- `C_FindObjects` is drained and symbolic object references are resolved by
  their downstream role rather than relying on unspecified enumeration order.
- Provisioned certificate values and RSA moduli are checked structurally, and
  generated signatures are checked for successful production and expected
  length instead of equality with another provider's bytes.

Every JSON result records the test name and official URL, XML SHA-256, module
path and SHA-256, selected slot, calls executed, and any semantic bindings
used. Cases that call `C_GetTokenInfo` also record the returned token metadata.
Retain the live result directory with the exact module binary and provisioning
record used for qualification.

These tests are useful conformance evidence, but neither this executor nor a CI
run is an OASIS certification. A conformance claim still needs a successful
run against the shipped production binary and actual provisioned token, scoped
to the named profile, plus the evidence and declarations required by the
claiming organization.

Official artifact directory:
<https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/os/test-cases/pkcs11-v3.2/mandatory/>
