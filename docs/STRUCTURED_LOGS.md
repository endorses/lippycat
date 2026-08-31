# Structured Protocol Logs

The structured protocol logging guide is part of the lippycat manual:

- [Structured Protocol Logs](manual/src/part5-advanced/structured-protocol-logs.md)

The versioned field and type contract remains in
[`structured-protocol-log-schema.md`](structured-protocol-log-schema.md).

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
