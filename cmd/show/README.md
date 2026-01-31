# Show Command - Processor Diagnostics

The `show` command displays information and diagnostics from running processors. Remote commands connect via gRPC and output JSON for easy parsing.

**Security:** TLS is enabled by default. Use `--insecure` for local testing without TLS.

## Commands

### Status

Show processor status and statistics.

```bash
# Show processor status (TLS with CA verification)
lc show status -P processor.example.com:55555 --tls-ca ca.crt

# Local testing without TLS
lc show status -P localhost:55555 --insecure
```

**Output:**
```json
{
  "processor_id": "central-proc",
  "status": "healthy",
  "total_hunters": 3,
  "healthy_hunters": 3,
  "warning_hunters": 0,
  "error_hunters": 0,
  "total_packets_received": 1250000,
  "total_packets_forwarded": 0,
  "total_filters": 5,
  "upstream_processor": ""
}
```

### Hunters

Show connected hunter details and statistics.

```bash
# List all connected hunters (TLS with CA verification)
lc show hunters -P processor.example.com:55555 --tls-ca ca.crt

# Show a specific hunter
lc show hunters -P processor.example.com:55555 --tls-ca ca.crt --hunter edge-01

# Local testing without TLS
lc show hunters -P localhost:55555 --insecure
```

**Output (list):**
```json
[
  {
    "hunter_id": "edge-01",
    "hostname": "capture-node-1",
    "remote_addr": "10.0.1.10:45678",
    "status": "healthy",
    "connected_duration_sec": 3600,
    "interfaces": ["eth0"],
    "stats": {
      "packets_captured": 500000,
      "packets_matched": 12500,
      "packets_forwarded": 12500,
      "packets_dropped": 0,
      "buffer_bytes": 1048576,
      "active_filters": 3
    },
    "capabilities": {
      "filter_types": ["sip_user", "ip_address"],
      "gpu_acceleration": true,
      "af_xdp": false
    }
  }
]
```

### Topology

Show the complete distributed topology.

```bash
# Show full topology (TLS with CA verification)
lc show topology -P processor.example.com:55555 --tls-ca ca.crt

# Local testing without TLS
lc show topology -P localhost:55555 --insecure
```

**Output:**
```json
{
  "processor_id": "central-proc",
  "address": ":55555",
  "status": "healthy",
  "hierarchy_depth": 0,
  "reachable": true,
  "hunters": [...],
  "downstream_processors": [
    {
      "processor_id": "region-east",
      "address": "10.0.2.1:55555",
      "status": "healthy",
      "hierarchy_depth": 1,
      "reachable": true,
      "hunters": [...]
    }
  ]
}
```

### Filter

Show filter details (see `cmd/filter` for full filter management).

```bash
# Show a specific filter (TLS with CA verification)
lc show filter --id myfilter -P processor.example.com:55555 --tls-ca ca.crt

# Local testing without TLS
lc show filter --id myfilter -P localhost:55555 --insecure
```

### Config

Show local TCP SIP configuration (no processor connection required).

```bash
# Show local configuration
lc show config

# JSON output
lc show config --json
```

## Connection Flags

All remote commands support these flags. **TLS is enabled by default.**

| Flag | Description |
|------|-------------|
| `-P, --processor` | Processor address (host:port) - **required** |
| `--insecure` | Allow insecure connections without TLS (must be explicitly set) |
| `--tls-ca` | Path to CA certificate file |
| `--tls-cert` | Path to client certificate file (mTLS) |
| `--tls-key` | Path to client key file (mTLS) |
| `--tls-skip-verify` | Skip TLS certificate verification (INSECURE - testing only) |

## Usage Examples

### Health Check Script

```bash
#!/bin/bash
# Check processor health (assumes TLS config in environment or config file)
status=$(lc show status -P processor:55555 --tls-ca /etc/lippycat/ca.crt 2>/dev/null | jq -r '.status')
if [ "$status" = "healthy" ]; then
    echo "OK"
else
    echo "UNHEALTHY: $status"
    exit 1
fi
```

### Monitor Hunter Count

```bash
# Watch hunter connections (local testing)
watch -n 5 'lc show status -P localhost:55555 --insecure | jq "{total: .total_hunters, healthy: .healthy_hunters}"'
```

### Export Topology

```bash
# Save topology to file
lc show topology -P processor:55555 --tls-ca ca.crt > topology-$(date +%Y%m%d).json
```

## Error Handling

Errors are output as JSON to stderr with appropriate exit codes:

```json
{"error":"processor address is required","code":"UNAVAILABLE"}
```

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Connection error |
| 3 | Validation error |
| 4 | Not found |

## See Also

- [cmd/filter/README.md](../filter/README.md) - Filter management commands
- [docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md) - Distributed architecture
- [docs/SECURITY.md](../../docs/SECURITY.md) - TLS/mTLS configuration
