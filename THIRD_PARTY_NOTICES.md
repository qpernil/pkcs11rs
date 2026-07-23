# Third-Party Notices

## OASIS PKCS #11 Headers

The repository includes byte-for-byte copies of `pkcs11.h`, `pkcs11f.h`, and
`pkcs11t.h` from the final OASIS PKCS #11 Specification Version 3.2 Standard
header set:

- <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11.h>
- <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11f.h>
- <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11t.h>

These files retain their OASIS copyright and distribution notices and are
subject to the OASIS IPR Policy referenced in those notices. They are not
relicensed under the repository's MIT or Apache-2.0 licenses.

The explicit `cargo xtask bindings` maintenance command uses these files as
`bindgen` inputs. The generated Rust source is stored in `src/pkcs11.rs`;
ordinary builds do not invoke `bindgen`.
