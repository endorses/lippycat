# Show Command - Processor Diagnostics

The `show` command displays information and diagnostics from running processors. Remote commands connect via gRPC and output JSON for easy parsing.

## Commands

### Status

Show processor status and statistics.

```bash
# Show processor status
lc show status -P localhost:50051

# With TLS
lc show status -P processor.example.com:50051 -T --tls-ca ca.crt
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
# List all connected hunters
lc show hunters -P localhost:50051

# Show a specific hunter
lc show hunters -P localhost:50051 --hunter edge-01

# With TLS
lc show hunters -P processor.example.com:50051 -T --tls-ca ca.crt
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
# Show full topology
lc show topology -P localhost:50051

# With TLS
lc show topology -P processor.example.com:50051 -T --tls-ca ca.crt
```

**Output:**
```json
{
  "processor_id": "central-proc",
  "address": ":50051",
  "status": "healthy",
  "hierarchy_depth": 0,
  "reachable": true,
  "hunters": [...],
  "downstream_processors": [
    {
      "processor_id": "region-east",
      "address": "10.0.2.1:50051",
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
# Show a specific filter
lc show filter --id myfilter -P localhost:50051
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

All remote commands support these flags:

| Flag | Description |
|------|-------------|
| `-P, --processor` | Processor address (host:port) - **required** |
| `-T, --tls` | Enable TLS encryption |
| `--tls-ca` | Path to CA certificate file |
| `--tls-cert` | Path to client certificate file (mTLS) |
| `--tls-key` | Path to client key file (mTLS) |
| `--tls-skip-verify` | Skip TLS certificate verification (insecure) |

## Usage Examples

### Health Check Script

```bash
#!/bin/bash
# Check processor health
status=$(lc show status -P localhost:50051 2>/dev/null | jq -r '.status')
if [ "$status" = "healthy" ]; then
    echo "OK"
else
    echo "UNHEALTHY: $status"
    exit 1
fi
```

### Monitor Hunter Count

```bash
# Watch hunter connections
watch -n 5 'lc show status -P localhost:50051 | jq "{total: .total_hunters, healthy: .healthy_hunters}"'
```

### Export Topology

```bash
# Save topology to file
lc show topology -P localhost:50051 > topology-$(date +%Y%m%d).json
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
