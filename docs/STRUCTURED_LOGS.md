# Structured Protocol Logs

The structured protocol logging guide is part of the lippycat manual:

- [Structured Protocol Logs](manual/src/part5-advanced/structured-protocol-logs.md)

The versioned field and type contract remains in
[`structured-protocol-log-schema.md`](structured-protocol-log-schema.md).

## RADIUS observations

RADIUS observations are available with `--log-streams radius` (and included in
the default stream set). The `radius` stream uses the same bounded queues,
overflow counters, TSV/JSONL encoders, rotation hooks, and graceful draining as
other streams. It records every message independently, including identity-free
responses and unsuccessful/ambiguous associations. It needs no LI task.
The [schema contract](structured-protocol-log-schema.md#radius-observation-stream-v1-additive-extension)
documents the exact attribute allowlist and binary representation; credentials,
authenticators and unknown attributes are absent from routine logs.

## RADIUS command selection

```bash
lc sniff radius -r radius.pcap --log-dir ./logs --log-streams radius
```

`sniff radius`, `tap radius`, and protocol-neutral `process` use the same optional
stream and schema. Dedicated `sniff radius` writes logs after ordinary selection
and reuses the same capture observation and scope as packet/CLI output, without
counting validation twice. Nonmatching competing requests still reach association
before selection. Logs do not activate LI, enable PCAP files, or establish capture
origin trust. Identity selection and transaction limits use shared `radius.*`
configuration. Each selected valid observation has its own record; an identity-free
response may carry a unique observational request association. Counters remain
separate from record fields. See [RADIUS operations](RADIUS.md) for state pressure,
scope and no-secret limitations. Synthetic direct hunt/process verification has
passed; external MDF/operator acceptance remains pending.

## Distributed event transport

Normalized events can be produced locally or forwarded by a hunter or tap with
`--forward-mode=events`. Event forwarding saves bandwidth, but it is not packet
forwarding: the upstream processor cannot reconstruct PCAPs, inject traffic into
a virtual interface, or repeat analysis that requires original packet bytes.
Deploy a tap when both are required: it can retain local PCAP evidence while
forwarding normalized events upstream.

Event mode is negotiated at registration. An incompatible event-mode session
fails unless `--event-fallback-to-packets` permits an explicit, logged fallback.
Packet mode remains the compatibility default. Reliable delivery uses a bounded
producer spool and processor ingress WAL; memory-only delivery is not
crash-durable. Inspect loss records and spool/WAL exhaustion warnings in either
profile.

## TUI subscriptions

TUI event subscription version 1 starts at a live boundary and never replays
events from before admission or during a disconnect. A reconnect cursor lets the
processor report an unrecoverable gap; it is not a replay request.

- **Transport loss** means an event was lost or omitted before reaching the TUI.
- **Local ring eviction** removes the oldest already-received row from the
  bounded display store and does not increase transport loss.

Treat normalized events as sensitive telemetry. TLS/mTLS protects transport,
but access and local files also require protection. Sensitive HTTP, SMTP, and
file fields require both a subscriber request and
`--event-allow-sensitive-fields`; file metadata additionally requires
`--event-allow-file-metadata`. File content is never carried by this event API.
