# Authentication secrets

- Follow [the authentication secret retention policy](docs/authentication-secrets.md).
- Do not retain ordinary login PINs/passwords or equivalent reusable
  authentication material for later operations by default. Retain only the
  authorization state, scoped tokens, or session keys required by the backend's
  documented lifetime; require fresh authentication when needed.
- Preserve the documented, explicit configuration exceptions. Any additional
  retention exception requires explicit opt-in, documentation of its scope and
  lifetime, and tests for default non-retention and cleanup.
- Keep secrets out of logs and debug output and use zeroizing storage for
  retained secret material. Do not weaken production authentication behavior
  to accommodate tests.
