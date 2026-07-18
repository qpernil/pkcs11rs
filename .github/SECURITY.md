# Security Policy

## Supported Versions

The project has not made a stable release. Security fixes are applied to the
latest revision of the `master` branch; older revisions are not maintained.

## Reporting a Vulnerability

Please report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/qpernil/pkcs11rs/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability.

Include the affected backend and device, firmware version, PKCS #11 operation,
mechanism, configuration, and a minimal reproducer when possible. Do not send
production PINs, private keys, secure-channel keys, or other live credentials.

If private vulnerability reporting is unavailable, contact the repository
owner privately through the contact information on their GitHub profile before
disclosing the issue publicly.

## Scope

Reports about secret exposure, authentication bypass, incorrect cryptographic
operations, unsafe FFI behavior, secure-channel failures, and unexpected
private-key extraction are in scope. Device firmware vulnerabilities should
also be reported to the relevant hardware vendor.
