# YubiHSM storage capacity

Hostnames and device/account identifiers below are illustrative; replace them with your own configured values.

Persistent objects share two independent budgets: 256 object records and
1,024 pages of 126 bytes (129,024 bytes). Authentication objects, keys and
opaque PKCS #11 metadata all consume this capacity. A companion shared by
private and public aspects consumes one record, not one per aspect.

## Verified allocation

The [physical measurements](yubihsm-storage-qualification.json) cover a Mac USB
HSM reporting firmware 2.4.1 and read-only inventories of two build-host HSMs
reporting 2.5.0. On the Mac, temporary opaque objects were created individually,
measured, deleted, and followed by complete inventory and storage-counter
comparisons. All nine probes restored the original inventory and free capacity.

| Opaque payload bytes | Pages allocated | Allocated bytes |
| ---: | ---: | ---: |
| 1, 125, 126 | 1 | 126 |
| 127, 166, 206, 251, 252 | 2 | 252 |
| 253 | 3 | 378 |

The build-host inventories contained 26 objects using 70 pages and 21 objects
using 51 pages. In both cases, summing each reported object length rounded up
to 126 bytes exactly matched the used-page counter. Those credentials allowed
reading but lacked opaque creation/deletion permissions; no changes were made
on those devices.

These results agree with Yubico's [GET STORAGE INFO description](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#get-storage-info-command).
The core charges the validated device-reported object length in whole pages,
with a minimum of one page. This is a device storage model, not host Rust/CBOR
heap allocation accounting.

## Cost of the current PKCS #11 policy

The capacity tests start with one factory authentication object and create keys
through the public PKCS #11 API until the next creation fails. Values below
assume no other objects or certificates. Public session objects live on the
host. Generated ordinary asymmetric keys imply a public token half;
non-default presence and attribute values may require a companion.

| Creation template | Device records per key/pair | Metadata bytes per companion (typical) | Metadata pages | Keys/pairs that fit |
| --- | ---: | ---: | ---: | ---: |
| AES with its full native encrypt/decrypt/sign/verify/derive permissions | 1 | 0 | 0 | 255 |
| AES requested for encrypt/decrypt, normalized to native permissions | 1 | 0 | 0 | 255 |
| AES with an explicit ECB mechanism list, normalized to native permissions | 1 | 0 | 0 | 255 |
| AES with an explicitly empty mechanism list | 1 | 0 | 0 | 255 |
| AES encrypt/decrypt with an 80-byte label | 2 | 193–194 | 2 | 127 |
| P-256 private token key, public session object (public absence marker) | 2 | 110–111 | 1 | 127 |
| P-256 private and public token objects, public `CKA_TOKEN` omitted or true | 1 | 0 | 0 | 255 |

CBOR integer widths make exact metadata lengths vary slightly with native IDs;
all tested records remain within the page counts shown. The object-record
limit is reached first for these templates. One companion per key reduces
this usable key count from 255 to 127 (about 50%). Default generated token pairs
use all 255 available native-key records, exposing 510 PKCS #11 key objects with
zero companion bytes. These measurements use P-256; larger native key material
can reach the page budget before the record limit.

AES encryption capability also enables operations used for signing and
key derivation. Creation uses [native permission granularity](yubihsm-capability-mapping.md)
and reports the effective usage and mechanisms instead of storing differences
from the input template. Explicit ECB and empty-list capacity tests also check
attributes and denied operations after logout/login, without metadata writes.
The native generated-origin bit supplies default public presence. Non-generated
imports default to private-only. Omitted public `CKA_TOKEN` defaults to a token
object for native token-pair generation. Explicit session-only public generation retains
an absence marker so discovery does not expose an extra token public object.

The common metadata save path removes native-default IDs, labels, and permission
values before deciding whether a record is necessary. A default-derived
`CKA_UNIQUE_ID` alone never requires storage. When no meaningful override or
non-default public presence remains, the old companion is deleted. Independent stored IDs,
public restrictions (including explicitly empty allowed-mechanism lists), and
legacy-shadow records retain their semantics. Obsolete native permission
overrides are ignored and removed on an explicit save. Discovery does not write metadata.

Creation failure reports `CKR_DEVICE_MEMORY` when device records or pages run
out. If native creation succeeded before companion persistence failed, the
provider attempts to remove the unreturned native object and its companions;
cleanup failures are logged. Generation, direct import, and unwrap share this
rollback path. Explicitly empty IDs are preserved by metadata, including after
unwrap. Tests verify rollback, preservation of existing keys, and reuse after
deletion.

The permission mapping deliberately accepts native-granularity PKCS #11
behavior. Identity, provenance, public-object lifecycle and explicit public
restrictions remain distinct reasons for retaining metadata. Shrinking a payload
within one 126-byte page saves neither a page nor an object slot; eliminating
an unnecessary companion recovers both resources.

## Deletion headroom

At 256 occupied device records, independently deleting either half of a
metadata-free pair may fail with `CKR_DEVICE_MEMORY`: public deletion needs an
absence marker, and private deletion must first persist the surviving public
material. Both failures leave the pair intact. With one spare record and enough
free pages, either transition can preserve the other object's lifetime. Keeping
254 default pairs plus the factory authentication key leaves one record for
these transitions. A pair that already has a companion can reuse that record
when preserving the public half. Native administration that deletes the entire
backing key is outside this independent PKCS #11 object-lifetime behavior.

## Reproduction

Run the simulated capacity regressions:

```sh
cargo test --locked --lib --all-features yubihsm_capacity -- --test-threads=1 --nocapture
```

For explicitly authorized physical measurement, `tools/yubihsm-storage-probe.py`
accepts either `--usb` or `--url`, explicit `--serial` selectors, `--sizes`, and an
`--output` path. It requires the official Python YubiHSM SDK (`pyusb` for USB)
and `requests`. Authentication Key 1 is the default selector; the password is
prompted interactively or read from standard input. Results contain no password.
It never fills a device or deletes existing objects.

Embedded virtual devices enforce hardware-like limits by default. The connector
option `--virtual-yubihsm-unlimited-storage` explicitly disables them for all
configured embedded HSMs. See the virtual device's
[storage model](https://github.com/qpernil/virtual-yubihsm/blob/main/docs/storage-capacity.md).
