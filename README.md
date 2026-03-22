# tls-cert-sync

A lightweight daemon that watches for TLS certificate files on the local filesystem and syncs them to remote systems. Designed to run in Kubernetes where renewable certificates are mounted as files, pairing naturally with cert-manager or similar tools.

## How it works

1. Reads `tls.crt` and `tls.key` from a configured directory
2. Connects to the remote system's API and checks whether the certificate needs to be deployed
3. Deploys the certificate if needed, in a target-specific way
4. Repeats on a configurable interval

The sync logic is idempotent.

## Supported targets

### TrueNAS

Uses the official [TrueNAS websocket API client](https://github.com/truenas/api_client_golang) to import certificates, activate them for the web UI, and restart the web service. Old certificates with the same name prefix are automatically cleaned up, keeping at most 2.

**Authentication**: Set the `SYNC_TRUENAS_API_KEY` environment variable to a TrueNAS API key.

## Usage

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--type` | `-t` | (required) | Target system type |
| `--url` | `-u` | (required) | Target system URL |
| `--cert-dir` | `-c` | `.` | Directory containing `tls.crt` and `tls.key` |
| `--interval` | `-i` | `300` | Sync interval in seconds |
| `--insecure` | `-k` | `false` | Skip TLS verification when connecting to the remote system |
| `--log-level` | `-l` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `--version` | `-v` | | Print version and exit |

**Example**:

```
export SYNC_TRUENAS_API_KEY=1-abc123...
tlscertsync \
  --type truenas \
  --url https://truenas.example.com \
  --cert-dir /certs \
  --interval 300
```

## Observability

- **Health**: `/healthz` on port 8080 — returns 200 when cert files are found and the remote system is reachable, 503 otherwise
- **Metrics**: `/metrics` on port 8080 — Prometheus metrics for the active certificate on the remote system:
  - `tlscertsync_target_cert_issuer`
  - `tlscertsync_target_cert_sn`
  - `tlscertsync_target_cert_notbefore`
  - `tlscertsync_target_cert_notafter`

## Building

```
go build -o tlscertsync .
```

To set a specific version:

```
go build -ldflags "-X github.com/tlscertsync/cmd.Version=v1.2.3" -o tlscertsync .
```

## License

Apache 2.0
