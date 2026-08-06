#!/bin/bash

set -euo pipefail

CONNECTOR_URL="http://127.0.0.1:12345"
EXPECTED_SERIAL=""
AUTHENTICATION_KEY="1"
DOMAIN="1"
REQUEST_COUNT=5
COMMAND_LIMIT_SECONDS=90
CHECK_ONLY=0
YUBIHSM_SHELL_BIN="${YUBIHSM_SHELL_BIN:-yubihsm-shell}"

usage() {
    cat <<'EOF'
Usage: tools/connector-scp-queue-test.sh --serial SERIAL [OPTIONS]

Guided physical disconnect/reconnect test for pkcs11rs-connector. The test
uses yubihsm-shell directly, establishes independent SCP sessions, and submits
five concurrent RSA-2048 key generations with object ID 0.

Options:
  --serial SERIAL       Required serial selected by the legacy SCP route.
  --connector URL       Connector base URL (default: http://127.0.0.1:12345).
  --authkey ID          Authentication-key ID (default: 1).
  --domain DOMAIN       Domain assigned to test keys (default: 1).
  --requests COUNT      Concurrent key generations (default: 5).
  --command-limit SEC   Harness safety limit per yubihsm-shell command
                        (default: 90; connector USB timeout remains separate).
  --check-only          Verify topology, credentials, and SCP without creating keys.
  -h, --help            Show this help.

Set YUBIHSM_TEST_PASSWORD in the environment, or the test will prompt for it.
The password is passed to yubihsm-shell, whose command line may be visible to
other processes owned by the same user while a command is running.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        die "$1 requires a value"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --serial)
            require_value "$@"
            EXPECTED_SERIAL="$2"
            shift 2
            ;;
        --connector)
            require_value "$@"
            CONNECTOR_URL="$2"
            shift 2
            ;;
        --authkey)
            require_value "$@"
            AUTHENTICATION_KEY="$2"
            shift 2
            ;;
        --domain)
            require_value "$@"
            DOMAIN="$2"
            shift 2
            ;;
        --requests)
            require_value "$@"
            REQUEST_COUNT="$2"
            shift 2
            ;;
        --command-limit)
            require_value "$@"
            COMMAND_LIMIT_SECONDS="$2"
            shift 2
            ;;
        --check-only)
            CHECK_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ -n "$EXPECTED_SERIAL" ]] || die "--serial is required"
[[ "$REQUEST_COUNT" =~ ^[1-9][0-9]*$ ]] || die "--requests must be a positive integer"
[[ "$COMMAND_LIMIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "--command-limit must be a positive integer"

CONNECTOR_URL="${CONNECTOR_URL%/}"

for command in curl grep jq sed "$YUBIHSM_SHELL_BIN"; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="$(command -v timeout)"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="$(command -v gtimeout)"
else
    die "GNU timeout is required (install coreutils on macOS)"
fi

PASSWORD="${YUBIHSM_TEST_PASSWORD:-}"
if [[ -z "$PASSWORD" ]]; then
    [[ -t 0 ]] || die "set YUBIHSM_TEST_PASSWORD when standard input is not a terminal"
    read -r -s -p "YubiHSM authentication password: " PASSWORD
    printf '\n'
fi

RUN_STAMP="$(date -u +%H%M%S)-$$"
LABEL_PREFIX="pkcs11rs-q-${RUN_STAMP}"
LOG_DIRECTORY="$(mktemp -d "${TMPDIR:-/tmp}/pkcs11rs-connector-queue.XXXXXX")"
MANIFEST="$LOG_DIRECTORY/labels.txt"
KEY_LABELS=()
WORKER_PIDS=()
WORKER_LOGS=()

printf 'Connector SCP queue test\n'
printf '  connector: %s\n' "$CONNECTOR_URL"
printf '  expected serial: %s\n' "$EXPECTED_SERIAL"
printf '  request count: %s\n' "$REQUEST_COUNT"
printf '  test-label prefix: %s\n' "$LABEL_PREFIX"
printf '  logs: %s\n' "$LOG_DIRECTORY"

curl_json() {
    curl --fail --silent --show-error --connect-timeout 3 --max-time 5 "$1"
}

assert_expected_device() {
    local devices matching status legacy_status legacy_serial
    devices="$(curl_json "$CONNECTOR_URL/v1/devices")" || return 1
    matching="$(printf '%s' "$devices" \
        | jq -er --arg serial "$EXPECTED_SERIAL" \
            '[.devices[] | select(.serial == $serial)] | length')" || return 1
    if [[ "$matching" != "1" ]]; then
        printf 'Expected serial %s exactly once, but connector reported:\n%s\n' \
            "$EXPECTED_SERIAL" "$devices" >&2
        return 1
    fi
    status="$(printf '%s' "$devices" \
        | jq -er --arg serial "$EXPECTED_SERIAL" \
            '.devices[] | select(.serial == $serial) | .status')" || return 1
    if [[ "$status" != "available" ]]; then
        printf 'Expected available serial %s, but connector reported:\n%s\n' "$EXPECTED_SERIAL" "$devices" >&2
        return 1
    fi

    legacy_status="$(curl_json "$CONNECTOR_URL/connector/status")" || return 1
    legacy_serial="$(printf '%s\n' "$legacy_status" | sed -n 's/^serial=//p')"
    if ! printf '%s\n' "$legacy_status" | grep -q '^status=OK$' \
        || [[ "$legacy_serial" != "$EXPECTED_SERIAL" ]]; then
        printf 'Legacy connector route does not select %s:\n%s\n' "$EXPECTED_SERIAL" "$legacy_status" >&2
        return 1
    fi
}

expected_device_is_absent() {
    local devices matching legacy_status legacy_serial
    devices="$(curl_json "$CONNECTOR_URL/v1/devices")" || return 1
    matching="$(printf '%s' "$devices" \
        | jq -er --arg serial "$EXPECTED_SERIAL" \
            '[.devices[] | select(.serial == $serial)] | length')" || return 1
    [[ "$matching" == "0" ]] || return 1

    legacy_status="$(curl_json "$CONNECTOR_URL/connector/status")" || return 1
    legacy_serial="$(printf '%s\n' "$legacy_status" | sed -n 's/^serial=//p')"
    if printf '%s\n' "$legacy_status" | grep -q '^status=OK$' \
        && [[ "$legacy_serial" == "$EXPECTED_SERIAL" ]]; then
        return 1
    fi
}

run_shell() {
    "$TIMEOUT_BIN" --signal=TERM "$COMMAND_LIMIT_SECONDS" \
        "$YUBIHSM_SHELL_BIN" \
        --connector "$CONNECTOR_URL" \
        --authkey "$AUTHENTICATION_KEY" \
        --password "$PASSWORD" \
        "$@"
}

scp_preflight() {
    local output
    output="$(run_shell \
        --action list-objects \
        --object-type asymmetric-key \
        --label "${LABEL_PREFIX}-none")"
    printf '%s\n' "$output"
    printf '%s\n' "$output" | grep -q '^Found 0 object(s)$'
}

cleanup_keys() {
    local label listing id failed=0
    printf '\nCleaning up test keys...\n'
    for label in "${KEY_LABELS[@]}"; do
        if ! listing="$(run_shell \
            --action list-objects \
            --object-type asymmetric-key \
            --label "$label")"; then
            printf '  WARNING: could not list keys with label=%s\n' "$label" >&2
            failed=1
            continue
        fi
        while IFS= read -r id; do
            [[ -n "$id" ]] || continue
            printf '  deleting label=%s id=0x%s\n' "$label" "$id"
            if ! run_shell \
                --action delete-object \
                --object-type asymmetric-key \
                --object-id "0x$id"; then
                printf '  WARNING: could not delete label=%s id=0x%s\n' "$label" "$id" >&2
                failed=1
            fi
        done < <(printf '%s\n' "$listing" \
            | sed -n 's/^id: 0x\([[:xdigit:]]\{4\}\), type: asymmetric-key.*/\1/p')
    done
    return "$failed"
}

generate_key() {
    local label="$1"
    run_shell \
        --action generate-asymmetric-key \
        --object-id 0 \
        --label "$label" \
        --domains "$DOMAIN" \
        --capabilities sign-pkcs \
        --algorithm rsa2048
}

assert_expected_device || die "target HSM is unavailable or the legacy SCP route selects another serial"
printf '\nSCP preflight (read-only):\n'
scp_preflight || die "could not establish SCP session or preflight listing was unexpected"

if [[ "$CHECK_ONLY" == "1" ]]; then
    printf '\nCHECK PASSED: topology, legacy selection, credentials, and SCP are ready.\n'
    exit 0
fi

for ((index = 1; index <= REQUEST_COUNT; index++)); do
    label="${LABEL_PREFIX}-${index}"
    KEY_LABELS+=("$label")
    printf '%s\n' "$label" >>"$MANIFEST"
done
RECOVERY_LABEL="${LABEL_PREFIX}-recovery"
KEY_LABELS+=("$RECOVERY_LABEL")
printf '%s\n' "$RECOVERY_LABEL" >>"$MANIFEST"
if [[ "${#RECOVERY_LABEL}" -gt 40 ]]; then
    die "generated test label exceeds the YubiHSM 40-byte limit: $RECOVERY_LABEL"
fi

printf '\nThe test is ready. Keep target serial %s connected; other HSMs may remain attached.\n' \
    "$EXPECTED_SERIAL"
printf 'Launching %s concurrent RSA-2048 generations now.\n' "$REQUEST_COUNT"

LIFECYCLE_LOG="$LOG_DIRECTORY/lifecycle.txt"
monitor_target_lifecycle() {
    local polls=0 detached_poll=-1
    local max_polls=$(((COMMAND_LIMIT_SECONDS + 60) * 4))
    while (( polls < max_polls )); do
        if expected_device_is_absent >/dev/null 2>&1; then
            if (( detached_poll < 0 )); then
                detached_poll=$polls
            fi
        elif (( detached_poll >= 0 )) \
            && assert_expected_device >/dev/null 2>&1; then
            printf '%s %s\n' "$detached_poll" "$polls" >"$LIFECYCLE_LOG"
            return 0
        fi
        polls=$((polls + 1))
        sleep 0.25
    done
    return 1
}

monitor_target_lifecycle &
LIFECYCLE_MONITOR_PID=$!

START_SECONDS="$(date +%s)"
for ((index = 0; index < REQUEST_COUNT; index++)); do
    worker_number=$((index + 1))
    worker_log="$LOG_DIRECTORY/worker-${worker_number}.log"
    WORKER_LOGS+=("$worker_log")
    (
        printf 'worker=%s start_seconds=%s label=%s\n' \
            "$worker_number" "$(date +%s)" "${KEY_LABELS[$index]}"
        set +e
        generate_key "${KEY_LABELS[$index]}"
        result=$?
        set -e
        printf 'worker=%s end_seconds=%s exit=%s\n' \
            "$worker_number" "$(date +%s)" "$result"
        exit "$result"
    ) >"$worker_log" 2>&1 &
    WORKER_PIDS+=("$!")
done

printf '\n>>> GENERATIONS SUBMITTED: unplug the HSM that begins generating, then reinsert it after a few seconds. <<<\n\n'

SUCCESS_COUNT=0
FAILURE_COUNT=0
for ((index = 0; index < REQUEST_COUNT; index++)); do
    if wait "${WORKER_PIDS[$index]}"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
    printf '%s\n' "--- worker $((index + 1)) ---"
    sed 's/^/  /' "${WORKER_LOGS[$index]}"
done
END_SECONDS="$(date +%s)"

printf '\nQueue phase completed in %s seconds: %s succeeded, %s failed.\n' \
    "$((END_SECONDS - START_SECONDS))" "$SUCCESS_COUNT" "$FAILURE_COUNT"
if [[ "$FAILURE_COUNT" == "0" ]]; then
    printf 'WARNING: every generation succeeded; the HSM was probably unplugged too late.\n' >&2
fi

if wait "$LIFECYCLE_MONITOR_PID"; then
    read -r detached_poll reattached_poll <"$LIFECYCLE_LOG"
    printf 'Connector observed detach approximately %s ms after launch and rediscovered the target %s ms later.\n' \
        "$((detached_poll * 250))" "$(((reattached_poll - detached_poll) * 250))"
    LIFECYCLE_OK=1
else
    printf 'WARNING: connector did not observe a complete target detach/reattach cycle.\n' >&2
    LIFECYCLE_OK=0
fi

printf '\nOpening a fresh SCP session and generating a recovery key...\n'
RECOVERY_OUTPUT="$LOG_DIRECTORY/recovery.log"
if generate_key "$RECOVERY_LABEL" >"$RECOVERY_OUTPUT" 2>&1; then
    sed 's/^/  /' "$RECOVERY_OUTPUT"
    printf 'Recovery generation succeeded.\n'
    RECOVERY_OK=1
else
    sed 's/^/  /' "$RECOVERY_OUTPUT" >&2
    printf 'Recovery generation failed.\n' >&2
    RECOVERY_OK=0
fi

if cleanup_keys; then
    CLEANUP_OK=1
else
    CLEANUP_OK=0
fi

unset PASSWORD

if [[ "$FAILURE_COUNT" -gt 0 && "$LIFECYCLE_OK" == "1" \
    && "$RECOVERY_OK" == "1" && "$CLEANUP_OK" == "1" ]]; then
    printf '\nTEST PASSED: queued requests terminated, reconnect succeeded, and test keys were removed.\n'
    exit 0
fi

printf '\nTEST INCOMPLETE OR FAILED. Logs and cleanup labels are in %s\n' "$LOG_DIRECTORY" >&2
exit 1
