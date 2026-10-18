# RSA validation performance qualification

Release measurements use three samples per size unless marked otherwise.
In-process before/after generation uses identical RNG seeds and asserts
matching moduli. Imports use identical keys; ordinary private-operation timing
excludes key creation. The baseline performs the previous library construction
and algebraic checks; the shared API additionally performs key-quality
validation and a pairwise test.

## In-process software costs

Measured on the development Mac, without concurrent Rust builds/tests. Values
are medians in milliseconds, shown as before → after. Timing noise and random
prime search prevent treating these figures as fixed latency guarantees.

| RSA bits | Generation | Private import | Public import | Private operation |
| --- | ---: | ---: | ---: | ---: |
| 1024 | 6.268 → 12.458 | 0.019 → 5.536 | <0.001 → 0.304 | 0.158 → 0.161 |
| 1280 | 22.199 → 27.111 | 0.024 → 9.617 | <0.001 → 0.573 | 0.316 → 0.268 |
| 2048 | 45.078 → 70.527 | 0.039 → 31.712 | <0.001 → 2.022 | 0.874 → 0.731 |
| 2304 | 125.485 → 174.743 | 0.045 → 48.127 | <0.001 → 2.994 | 1.017 → 1.018 |
| 3072 | 140.829 → 252.250 | 0.065 → 111.385 | <0.001 → 6.919 | 2.095 → 2.111 |
| 4096 | 746.611 → 1052.557 | 0.096 → 313.889 | 0.001 → 16.886 | 4.713 → 4.712 |

The import cost is paid once. Trusted persistence restoration, cloning, signing
and decryption do not repeat primality testing. The paired private-operation
measurements show no systematic operation-time penalty. Legacy sizes in this
table exercise validation coverage; they are not NIST size-policy approvals.

## End-to-end virtual HSM costs

The connector benchmark uses published Wycheproof RSA-2048/3072/4096 fixtures,
fresh authenticated sessions, random temporary labels, device-assigned IDs,
and ownership-checked deletion. Every recorded sample confirms restoration of
the full visible object inventory. Private import sends only p and q. Public
import sends only n. Generation searches for fresh primes.

The same signed release client measures both firmware phases on each I2C
target; validation of fixture keys on the client occurs outside the measured
command. Pi firmware is built on ubuntu4 and deployed as a committed ARM64
prebuilt through Git. Existing credentials and persistent state are preserved.

Both I2C targets identify as Raspberry Pi 3 Model B Plus Rev 1.3, using the
ondemand governor with a 1.4 GHz maximum. Their before prebuilt uses the earlier
shared core; the after prebuilt also includes the reviewed stable dependency
refresh. End-to-end numbers describe the complete deployed upgrade. The paired
in-process experiment holds dependencies constant to isolate validation.

Values below are medians in milliseconds, shown as before → after.

| Target | RSA bits | Private import | Public import | Generation |
| --- | ---: | ---: | ---: | ---: |
| ubuntu4 embedded | 2048 | 1.201 → 243.090 | 1.025 → 19.560 | 329.921 → 961.488 |
| ubuntu4 embedded | 3072 | 1.214 → 892.445 | 1.024 → 65.328 | 1232.689 → 2802.770 |
| ubuntu4 embedded | 4096 | 1.353 → 2471.038 | 1.087 → 127.361 | 7332.245 → 6489.719 |
| raspberrypi-1 | 2048 | 10.477 → 997.305 | 9.819 → 70.423 | 1252.796 → 5083.836 |
| raspberrypi-1 | 3072 | 13.106 → 3878.298 | 12.877 → 241.288 | 10890.431 → 11640.761 |
| raspberrypi-1 | 4096 | 16.556 → 10523.166 | 15.978 → 534.085 | 56484.285 → 48732.649 |
| raspberrypi-2 | 2048 | 10.530 → 930.350 | 9.897 → 72.403 | 1214.108 → 2385.896 |
| raspberrypi-2 | 3072 | 13.059 → 3537.293 | 12.591 → 203.392 | 6340.157 → 9069.336 |
| raspberrypi-2 | 4096 | 16.738 → 10277.094 | 15.923 → 516.828 | 12674.877 → 30811.874 |

Generation is not paired by RNG seed in these end-to-end runs. With only three
samples, its differences cannot isolate validation overhead. The in-process
paired experiment provides the stronger comparison for generation overhead.

All 162 planned end-to-end samples passed, with object inventories restored.
Two supplemental RSA-4096 import confirmation samples are listed separately in
the data and excluded from the planned three-sample medians. The interrupted
attempt's uniquely labelled temporary object was inspected and deleted; only
completed, cleanup-verified measurements enter the tables.

[Machine-readable samples](rsa-validation-performance.json) contain no private
keys or authentication credentials. The shared validation design and NIST
references are documented in
[software-key-core](https://github.com/qpernil/software-key-core/blob/main/docs/rsa-key-validation.md).
