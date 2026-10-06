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

When media admission is enabled, `rtp_ebpf.scopes[].uncertainty` reports unique
unknown-call totals and overlapping reason counts. Duplicate counters count
messages with repeated singleton header groups, separately for CSeq, RSeq and
RAck; they are cumulative and distinct from active uncertainty. Do not sum
reason counts as a call total. `malformed_rseq` and `malformed_rack` count each
malformed header kind once per parsed message, including retransmissions; invalid
duplicate groups also count as conflicting duplicates.

`replay_guards` and `replay_guard_bytes` show per-domain usage, while
`replay_guard_capacity` and `replay_guard_byte_limit` are shared pool limits.
`replay_window_ns` is the configured protection window, `replay_unrecorded`
counts failed guard insertion attempts, and `replay_degraded_ns` is the remaining
domain-wide conservative interval. Zero remaining time means the interval is
inactive; sustained overload may extend it. Older peers omit these additive
fields. The additive
`degraded_duration_ns` reports current elapsed degradation for open, closed and
control-failed states; `open_duration_ns` retains cumulative confirmed-open time.
These fields contain no call identities, endpoint addresses or raw errors. See
[media admission diagnostics](../../docs/VOIP_EBPF_ADMISSION.md#failure-and-diagnostic-modes).

When LI delivery is configured, status also includes `li_delivery` with aggregate
X2/X3 enqueue, written, dropped, retry, and queue-depth statistics. Its
`destinations` object is keyed by destination UUID and includes separate X2/X3
queue depths and capacities, oldest queued ages, drop reasons, connection errors,
and `x2_keepalive` / `x3_keepalive` health. `li_encoding` remains a separate set
of encoding counters. Unavailable LI telemetry is omitted.

`x2_enqueue_calls` and `x3_enqueue_calls` count successful asynchronous enqueue
calls, including calls with no eligible destinations; written and dropped
counters count destination copies, so fan-out prevents direct reconciliation.
Written means a completed local TLS write, and keepalive ACKs indicate control
responsiveness; neither proves the receiver accepted a product. Monitor queue age
for current delay and changes in cumulative drop counters for loss. Counters reset
on restart, and destination details disappear when that destination is removed.
See [LI delivery telemetry](../../docs/LI_INTEGRATION.md#delivery-telemetry) for
field semantics and troubleshooting.

`storage.filters` reports the actual managed snapshot owner as `yaml`,
`encrypted`, or `disabled`. LI-enabled processors also report `storage.li_state`;
its mode is `disabled` when administrative persistence is not configured. X2
journal storage appears at `li_delivery.x2_journal.storage`. These fields contain
no store paths, selectors, task/call identifiers, payloads, or key material.
Configured key IDs are public operator labels and should not contain sensitive
information. No `x3_journal` field is emitted until durable X3 ownership exists.

Each store reports `state` (`unopened`, `ready`, `faulted`, `closing`, `closed`),
`admission_blocked`, fixed fault categories, and the last mutation outcome.
Snapshot counters count backend **Save attempts**, so one administrative request
can increment them several times. X2 counters count accepted product persistence
attempts (including their checkpoints) and individual durable record removals;
they exclude startup repair and offline operations. `commits`, `definite_failures`,
`uncertain`, and `committed_cleanup_warnings` reset with the owner. A committed
cleanup warning means the data committed even though later cleanup reported an
error. Administrative `policy_fault_code=reconciliation_required` can block
admission while the physical store is still `ready`.

Encrypted owners expose the loaded active/prior key IDs and `key_usage`.
`reserved_invocations` and `reserved_blocks` include unused reservations that
will be consumed on restart; a block represents 16 bytes of authenticated or
encrypted accounting volume, including framing overhead. Remaining capacities
are conservative bounds, not exact record/payload capacities. Rotation is
recommended at 75% of either hard limit; ordinary mutations stop at 90%, with
the final allowance reserved for controls. The limits are `2^32` invocations and
`2^40` blocks. A faulted ledger cannot be used to resume writes merely because
its diagnostic remaining count is positive.

`key_usage.reservation_outcome` describes the ledger update, separately from
the object's `last_outcome`: an uncertain ledger write can prevent encryption
entirely, leaving the object definitely uncommitted. These persistence outcomes
are also distinct from delivery `uncertain_writes`/`uncertain_bytes`, which
describe ambiguous local transport writes. Status reads use in-memory snapshots
and do not wait for filesystem synchronization.

| Fault category                                                                         | Operator action                                                                                                  |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `key_exhausted`                                                                        | Rotate offline before further ordinary writes.                                                                   |
| `usage_ledger_fault`, `identity_mismatch`, `authentication_failed`, `invalid_envelope` | Stop admission and reconcile the original store, ledger and configured keys offline; do not recreate accounting. |
| `required_file_missing`, `ownership_conflict`, `permission_denied`                     | Check provisioning, exclusive ownership and private-directory/key permissions.                                   |
| `capacity_exhausted`                                                                   | Restore space/quota, then reconcile any uncertain operation.                                                     |
| `storage_error`, `reconciliation_required`                                             | Treat the reported outcome as authoritative; repair/reconcile storage before restarting the owner.               |
| `migration_required`                                                                   | Explicitly upgrade the legacy read-only journal offline.                                                         |
| `closed`                                                                               | The owner has shut down; construct a new validated owner to resume.                                              |

### Hunter

Show details for a specific hunter.

```bash
# Show a specific hunter (TLS with CA verification)
lc show hunter --id edge-01 -P processor.example.com:55555 --tls-ca ca.crt

# Local testing without TLS
lc show hunter --id edge-01 -P localhost:55555 --insecure
```

> **Note:** To list all connected hunters, use `lc list hunters -P processor:55555 --tls-ca ca.crt`.

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

| Flag                | Description                                                     |
| ------------------- | --------------------------------------------------------------- |
| `-P, --processor`   | Processor address (host:port) - **required**                    |
| `--insecure`        | Allow insecure connections without TLS (must be explicitly set) |
| `--tls-ca`          | Path to CA certificate file                                     |
| `--tls-cert`        | Path to client certificate file (mTLS)                          |
| `--tls-key`         | Path to client key file (mTLS)                                  |
| `--tls-skip-verify` | Skip TLS certificate verification (INSECURE - testing only)     |

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
{ "error": "processor address is required", "code": "UNAVAILABLE" }
```

| Exit Code | Meaning          |
| --------- | ---------------- |
| 0         | Success          |
| 1         | General error    |
| 2         | Connection error |
| 3         | Validation error |
| 4         | Not found        |

## See Also

- [cmd/filter/README.md](../filter/README.md) - Filter management commands
- [docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md) - Distributed architecture
- [docs/SECURITY.md](../../docs/SECURITY.md) - TLS/mTLS configuration

LI delivery status also includes `queue_bytes`, `dropped_bytes`, per-destination
X2/X3 queued and in-flight bytes and byte capacities, `x3_expired`, and
`dropped_bytes_by_reason`. Independent `x2_journal` and `x3_journal` report byte pressure,
`pending`/`persisted`/`held`, `approved`/`retained` gauges and
`expired`/`revoked`/`rejected` counters. Each journal reports its own storage fault,
commit uncertainty and encryption usage separately from transport uncertainty.
Pending admission is not a durability
acknowledgement; held records require explicit replay authorization.

LI-enabled processor status includes `li_definitions` with aggregate `incomplete`,
`pull_only`, `conflicts`, `unknown_windows`, and `open_ended` gauges plus a
manager-lifetime `repairs` counter. Strict candidates contribute to incomplete
counts; unknown mediation windows are distinct from explicitly open-ended
definitions. The object is absent when LI is disabled or unavailable, and never
contains task, target, or destination labels.
