# Voucher Transmission & Push Guide

This document explains how vouchers leave the manufacturing station after they are created, how push destinations are resolved, how retries are handled, and how to operate the new CLI tools.

## Overview

When a voucher is emitted by the DI flow, the callback pipeline now:

1. Persists the `.fdoov` file in the GUID-based file store (if enabled) so we have an artifact for retries.
2. Runs the **Destination Resolver** to determine where the voucher should go.
3. Records a row in the `voucher_transmissions` table with metadata (destination, attempts, last error, serial/model).
4. Immediately attempts an HTTP push using the configured mode.
5. Schedules retries for transient failures while leaving a permanent audit trail of each attempt.

## Destination Resolution Order

The resolver inspects configuration in the following order:

1. **Destination Callback** (`voucher_management.destination_callback`)
   - Executes an external command with `{serialno}`, `{model}`, `{guid}` substitutions.
   - The script returns a URL that receives the voucher.
2. **Owner DID URL** (`voucher_management.did_push`)
   - If the owner resolution returned a DID document with a `voucherRecipientURL`, that becomes the destination.
3. **Static Push Service** (`voucher_management.push_service`)
   - Falls back to the statically configured URL/token pair.

If all three options fail or are disabled, the voucher is left on disk and in the database for manual action.

## Retry Worker

`VoucherRetryWorker` runs inside the server process (enabled via `voucher_management.retry_worker`). It wakes up on the configured `retry_interval`, pulls pending rows whose `retry_after` has elapsed, and calls `VoucherPushService.AttemptRecord` to re-use the same HTTP client + metadata. Retries stop when either:

- The push succeeds (row moves to `succeeded` and `delivered_at` is set), or
- `max_attempts` is reached, at which point the record becomes `failed` (permanent) and the next operator action is manual.

## CLI Reference

Run the binary with the desired command flag **before** starting the server. All commands honor `--config` for DB credentials.

### List transmissions

```bash
./fdo-manufacturing-station --config config.yaml \
  --voucher-list \
  --voucher-status pending \
  --voucher-guid deadbeef... \
  --voucher-limit 10
```

Columns: ID, GUID, status, attempt count, destination + source, next retry window, last error (truncated), updated timestamp.

### Retransmit a specific row

```bash
./fdo-manufacturing-station --config config.yaml --voucher-retransmit-id 42
```

This rehydrates the resolver (callback/DID/static), reuses the stored voucher file, and performs another HTTP push immediately. Logs are emitted via `slog` for traceability.

### Purge a row (and optional file)

```bash
./fdo-manufacturing-station --config config.yaml --voucher-purge-id 42
```

Deletes the voucher file if it still exists, then removes the transmission metadata row.

> **Tip:** Use `--voucher-list` frequently to monitor queue depth and investigate failures before purging.

## Configuration Cheatsheet

| Section | Key | Purpose |
| --- | --- | --- |
| `voucher_management.destination_callback` | `enabled`, `external_command`, `timeout` | Dynamic destination lookup via script |
| `voucher_management.did_push` | `enabled` | Allows DID-derived URLs to be used |
| `voucher_management.push_service` | `enabled`, `url`, `auth_token`, `mode`, `retry_interval`, `max_attempts`, `delete_after_success` | Static HTTP push configuration + retry tuning |
| `voucher_management.retry_worker` | `enabled`, `retry_interval`, `max_attempts` | Background worker scheduling |
| `voucher_management.voucher_files.directory` | `path` | Retains `.fdoov` files for CLI + audit |

## Database Schema

`voucher_transmissions` tracks every enqueue and retry:

- `voucher_guid`, `serial_number`, `model_number`
- `destination_url`, `destination_source`, `auth_token`
- `status` (`pending`, `succeeded`, `failed`, `failed_permanent`)
- Attempt counters, timestamps, `last_error`, and `retry_after`

Use the CLI to inspect or purge records instead of modifying the table manually.

## Operational Flow

1. Configure callback(s) and push service settings in `config.yaml`.
2. Start the manufacturing station; vouchers will begin populating the table automatically.
3. Monitor logs and/or `--voucher-list` for pending rows.
4. Let the retry worker handle transient network issues; intervene with `--voucher-retransmit-id` only when necessary.
5. Purge rows when they are no longer needed (after successful delivery or manual export).

Keeping vouchers in the database plus filesystem provides a fully traceable handoff history and makes customer support significantly easier.

## Automated Tests

Two integration tests now exercise the voucher egress paths end-to-end:

1. `tests/test_disk_save.sh` – Verifies the callback pipeline can sign, save, and validate vouchers on disk using the mock HSM signer.
2. `tests/test_voucher_push.sh` – Spins up the new `voucher-push-receiver` helper (listens on `localhost:9090/push`), runs the manufacturing station with `tests/config_push_test.cfg`, and confirms the pushed multipart upload matches the `.fdoov` file saved locally while logging metadata for later inspection.

Both scripts are wired into `tests/run_all_tests.sh`, so CI must keep them green before considering voucher push work “done.”
