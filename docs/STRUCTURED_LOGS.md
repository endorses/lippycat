# Structured Protocol Logs

The structured protocol logging guide is part of the lippycat manual:

- [Structured Protocol Logs](manual/src/part5-advanced/structured-protocol-logs.md)

The versioned field and type contract remains in
[`structured-protocol-log-schema.md`](structured-protocol-log-schema.md).

## DHCP, NTP, and local inventories

The default seven streams remain `conn,dns,ssl,http,smtp,files,radius`. Select
`dhcp`, `ntp`, `known_hosts`, and `known_services` explicitly with `--log-streams`:

```bash
lc sniff -r network.pcap --log-dir ./logs --log-streams dhcp,ntp
sudo lc tap -i eth0 --insecure --inventory \
  --inventory-local-cidrs 192.0.2.0/24,2001:db8::/32 \
  --log-dir ./logs --log-streams dhcp,ntp,known_hosts,known_services
```

DHCPv4 and NTP time messages produce one record per accepted datagram, including
protocol retransmissions, rather than Zeek-style transaction/session aggregates.
Separate association IDs retain exchange context without replacing observed flow
UIDs or endpoints. Incomplete input is explicit; binary identifiers and raw NTP
timestamps retain safe, exact representations. BOOTP/DHCPv6, NTP control/private
analysis, authentication, and clock-offset conclusions are outside these logs.
Typed events remain available without file logging.

Inventory events are enabled by default for all observed eligible unicast hosts
and services. Disable them with `--inventory=false`, or optionally restrict
subjects with IPv4/IPv6 `--inventory-local-cidrs`. CIDRs do not restrict packet
capture. Only explicitly configured CIDRs classify connection endpoints as local;
an empty list does not mark every observed address as local. Known
hosts require an observed completed TCP handshake or both UDP directions; known
services additionally require a reliably oriented responder and actual protocol
analysis. Ports, cached labels, lone SYNs, destination addresses, and DHCP offers
are insufficient. Inventory events emit as soon as the required packet evidence
is available; connection summaries retain their existing expiry, eviction, and
EOF/reset/close behavior. Relays do not derive inventory again. Global/per-scope
entry and byte caps and a capture-time retention window bound state;
expiry/eviction permit re-emission. Scope separates sensors, epochs, interfaces,
and offline inputs. Policy changes participate in producer identity.

DHCP identifiers/names and inventory details are sensitive. Subscribers need
sensitive-field permission; unauthorized inventory events are omitted with
explicit policy-loss accounting. Explicit local logs include sensitive fields,
so protect file access and retention. Older peers can carry existing workloads;
unsupported optional kinds report compatibility loss, while required streams
must negotiate successfully or use explicitly configured packet fallback.

See the [operator guide](manual/src/part5-advanced/structured-protocol-logs.md#network-observations),
[shared settings and defaults](manual/src/appendices/config-reference.md#network-observation-settings),
and [canonical schema](structured-protocol-log-schema.md) for exact fields,
association bounds, positive evidence, privacy, and lifecycle behavior.

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
but access and local files also require protection. Sensitive HTTP, SMTP, DHCP, inventory, and
file fields require both a subscriber request and
`--event-allow-sensitive-fields`; file metadata additionally requires
`--event-allow-file-metadata`. File content is never carried by this event API.
