# Voucher Push Receiver

A lightweight HTTP server used for demos and integration tests to confirm that vouchers pushed by the manufacturing station arrive intact. It listens for multipart uploads, validates an optional bearer token, writes the `.fdoov` payload to disk, and records basic metadata alongside it.

## When to use it

- Local testing of the voucher push pipeline (e.g., `tests/test_voucher_push.sh`).
- Manual demos of DI + voucher delivery without involving a real customer endpoint.
- Debugging delivery failures by capturing the exact payload the push service emits.

## Command-line options

| Flag | Default | Description |
| --- | --- | --- |
| `-addr string` | `":9090"` | Address/port to listen on. Use `0.0.0.0:9090` to accept remote traffic. |
| `-dir string` | `/tmp/fdo_push_receiver` | Directory where received vouchers and metadata JSON files are written. |
| `-token string` | empty | Expected bearer token. When set, the receiver enforces `Authorization: Bearer <token>`. Leave empty to disable auth. |
| `-log string` | `/tmp/fdo_push_receiver.log` | Log file capturing uploads and errors. Set to `"-"` or empty to log to stdout/stderr. |

## Typical workflow

1. **Start the receiver**
   ```bash
   mkdir -p /tmp/fdo_push_receiver_demo
   ./voucher-push-receiver \
     -addr ":9090" \
     -dir /tmp/fdo_push_receiver_demo \
     -token demo-token \
     -log /tmp/fdo_push_receiver_demo.log
   ```
   The log will contain lines such as `voucher push receiver listening on :9090, dir=/tmp/fdo_push_receiver_demo`.

2. **Configure the manufacturing station** (e.g., `tests/config_push_test.cfg`):
   ```yaml
   voucher_management:
     push_service:
       enabled: true
       url: "http://localhost:9090/push"
       auth_token: "demo-token"
       mode: "send_always"
   ```

3. **Run DI / voucher creation**. Once a voucher is generated and pushed, the receiver writes:
   - `GUID.fdoov` – raw voucher payload saved exactly as delivered.
   - `GUID.json` – metadata including GUID, serial, model, and timestamp.

## Verifying delivery

After the DI run completes:

```bash
ls /tmp/fdo_voucher_files_push        # server-side retained voucher
ls /tmp/fdo_push_receiver_demo         # pushed voucher + metadata
cmp /tmp/fdo_voucher_files_push/GUID.fdoov /tmp/fdo_push_receiver_demo/GUID.fdoov
cat /tmp/fdo_push_receiver_demo/GUID.json
```

Matching payloads plus the `received voucher` log entry confirm that the push service successfully delivered the artifact to the receiver.

## Advanced receiver (introspection mode)

For deeper debugging there is an "advanced" variant at `cmd/advancer_voucher_recipient`. It shares the same CLI flags as the basic receiver but adds:

- Voucher metadata emitted directly to stdout (no `GUID.json` file requirement).
- Inline parsing of the pushed voucher using `go-fdo`, logging manufacturer key details and each voucher entry's public key / hash chain.

To exercise it with the existing integration test, build it and override the receiver binary:

```bash
go build -o advanced-voucher-recipient ./cmd/advancer_voucher_recipient
RECEIVER_BIN=$PWD/advanced-voucher-recipient tests/test_voucher_push.sh
```

The resulting `/tmp/fdo_push_receiver.log` will include the enriched voucher summary for quick inspection.
