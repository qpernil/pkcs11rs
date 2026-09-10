# Patched dependencies

## hidapi 2.6.6

`hidapi/` contains the published hidapi 2.6.6 crate, including its bundled
HIDAPI 0.15.0 C backend and original licenses. Cargo cache markers and the
upstream crate's standalone lockfile are omitted.

The only source change is in `etc/hidapi/mac/hid.c`: the global IOHIDManager
is scheduled on the current CFRunLoop for each `hid_enumerate` call and
unscheduled before that call returns. Its initialization does not attach a
run loop. The Rust wrapper serializes enumeration and never deinitializes
the C backend, so retaining the first caller's run loop can outlive that
thread and crash subsequent callers in `CFRunLoopAddSource`.

The regression `hid_inventory_survives_short_lived_callers` exercises
enumeration from overlapping, short-lived threads without opening devices.
Remove this Cargo patch when an upstream release provides equivalent
run-loop lifetime handling.
