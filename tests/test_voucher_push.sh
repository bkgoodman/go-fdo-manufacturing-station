#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_BIN="$PROJECT_ROOT/fdo-manufacturing-station"
RECEIVER_BIN="${RECEIVER_BIN:-$PROJECT_ROOT/voucher-push-receiver}"
CONFIG_FILE="$PROJECT_ROOT/tests/config_push_test.cfg"
CLIENT_SOURCE="$PROJECT_ROOT/go-fdo/examples/cmd"
CLIENT_BIN="$PROJECT_ROOT/fdo-di-client"

SERVER_LOG="/tmp/fdo_push_server.log"
RECEIVER_LOG="/tmp/fdo_push_receiver.log"
RECEIVER_DIR="/tmp/fdo_push_receiver"
VOUCHER_DIR="/tmp/fdo_voucher_files_push"
DB_PATH="/tmp/fdo_push_test.db"
PUSH_TOKEN="test-token"

SERVER_PID=""
RECEIVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$RECEIVER_PID" ] && kill -0 "$RECEIVER_PID" 2>/dev/null; then
        kill "$RECEIVER_PID" 2>/dev/null || true
        wait "$RECEIVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

rm -rf "$RECEIVER_DIR" "$VOUCHER_DIR" "$DB_PATH" "$SERVER_LOG" "$RECEIVER_LOG"
mkdir -p "$RECEIVER_DIR"

printf "=== Voucher Push Integration Test ===\n"

printf "Building server and receiver...\n"
(
    cd "$PROJECT_ROOT"
    go build -o fdo-manufacturing-station .
    go build -o voucher-push-receiver ./cmd/voucher_push_receiver
    (
        cd "$CLIENT_SOURCE"
        go build -o "$CLIENT_BIN"
    )
)

printf "Starting HTTP receiver...\n"
"$RECEIVER_BIN" -addr ":9090" -dir "$RECEIVER_DIR" -token "$PUSH_TOKEN" -log "$RECEIVER_LOG" >/dev/null 2>&1 &
RECEIVER_PID=$!
sleep 1
if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
    printf "❌ Receiver failed to start\n"
    exit 1
fi
printf "✅ Receiver started (PID %s)\n" "$RECEIVER_PID"

printf "Starting manufacturing station...\n"
"$SERVER_BIN" -config "$CONFIG_FILE" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    printf "❌ Server failed to start\n"
    cat "$SERVER_LOG"
    exit 1
fi
printf "✅ Server started (PID %s)\n" "$SERVER_PID"

printf "Triggering DI client...\n"
if ! timeout 20s "$CLIENT_BIN" client -di http://localhost:8080 >/dev/null 2>&1; then
    printf "⚠️  Client exited with non-zero status (continuing to inspect outputs)\n"
fi

# Wait for push receiver to get a file
FOUND="false"
ATTEMPTS=0
while [ "$ATTEMPTS" -lt 20 ]; do
    if ls "$RECEIVER_DIR"/*.fdoov >/dev/null 2>&1; then
        FOUND="true"
        break
    fi
    ATTEMPTS=$((ATTEMPTS + 1))
    sleep 1
done

if [ "$FOUND" != "true" ]; then
    printf "❌ Receiver did not get a voucher file\n"
    tail -n 40 "$SERVER_LOG" || true
    exit 1
fi

SOURCE_FILE="$(ls "$VOUCHER_DIR"/*.fdoov | head -n 1)"
RECEIVED_FILE="$(ls "$RECEIVER_DIR"/*.fdoov | head -n 1)"

if [ ! -f "$SOURCE_FILE" ]; then
    printf "❌ No voucher saved locally for comparison\n"
    exit 1
fi
if [ ! -f "$RECEIVED_FILE" ]; then
    printf "❌ Receiver file missing\n"
    exit 1
fi

GUID="$(basename "$SOURCE_FILE")"
GUID="${GUID%.fdoov}"
EXPECTED_RECEIVER_FILE="$RECEIVER_DIR/$GUID.fdoov"
if [ ! -f "$EXPECTED_RECEIVER_FILE" ]; then
    printf "❌ Receiver file for GUID %s not found\n" "$GUID"
    ls "$RECEIVER_DIR"
    exit 1
fi

if ! cmp -s "$SOURCE_FILE" "$EXPECTED_RECEIVER_FILE"; then
    printf "❌ Voucher file mismatch between disk store and receiver\n"
    exit 1
fi
printf "✅ Voucher payload matches between disk and receiver\n"

META_FILE="$RECEIVER_DIR/$GUID.json"
if [ -f "$META_FILE" ]; then
    printf "ℹ️  Legacy metadata file produced at %s\n" "$META_FILE"
fi

if ! grep -q "voucher transmission delivered" "$SERVER_LOG"; then
    printf "❌ Server log did not report successful push\n"
    tail -n 40 "$SERVER_LOG" || true
    exit 1
fi
printf "✅ Server log shows successful transmission\n"

printf "Voucher push test completed successfully.\n"
