# Selective VoIP media capture with eBPF

See the [implementation plan](plans/voip-ebpf-media-admission.md) and
[verification results](plans/voip-ebpf-implementation-results.md) for the tested
behavior and qualification limits. The [research report](research/voip-ebpf-media-admission.md)
records the design decisions.

`lc hunt voip --rtp-ebpf` and `lc tap voip --rtp-ebpf` enable Linux socket-level
admission of media candidates. The feature is off by default. Other commands keep
their existing capture behavior. libpcap still reads packets; a persistent eBPF
socket filter consults maps updated when selected calls gain or lose media
endpoints. Call activity does not restart capture, replace its socket/program, or
call `SetBPFFilter`.

```bash
sudo lc hunt voip -i eth0 --processor processor:55555 \
  --tls-ca ca.crt --rtp-ebpf

sudo lc tap voip -i eth0 --sip-user alice --rtp-ebpf \
  --tls-cert server.crt --tls-key server.key
```

## Capture and selection

The kernel admits candidates. Existing userspace checks remain authoritative for
call ownership, filter provenance, authorization, expiry, and output. A matching
endpoint does not assign a Call-ID or authorize delivery. Independent IP/CIDR
selectors and the configured no-filter policy continue to work; an empty IP
selector map alone does not mean there are no filters.

With `--rtp-ebpf`, including shadow mode, hunt and tap IP/CIDR selectors can select
eligible media independently of a selected call, subject to explicit packet
predicates and userspace output checks. With eBPF disabled, tap routes IP/CIDR
filters through classic BPF. A mixed IP and SIP-identity configuration can capture
IP-matched RTP but reject it in userspace without a selected-call association;
disabling admission does not preserve that output for unassociated media. True
IP-only tap configurations have no SIP-identity filter requiring the association.
Hunter IP/CIDR media selection remains independent with eBPF enabled or disabled.

For call-selected media, selective capture starts after selection and endpoint
publication.
There is no pre-match RTP history. Bounded SDP metadata from validated, unmatched
SIP messages can be promoted when the same dialog later matches. Promotion does
not recover packets already rejected by the kernel. Media arriving between SIP
selection and map publication can also be lost. Offer/answer and provisional SDP
can supply endpoints before a call is answered.

The shared parser recognizes IPv4/IPv6 connection addresses, media-level
overrides, multiple RTP streams, default and explicit RTCP endpoints, and RTCP
mux. Disabled or inactive descriptions contribute no new endpoints. The existing
call policy retains accepted endpoints until authoritative cleanup, including
trailing-media grace; a new description does not silently remove an opposite-side
or previously valid endpoint. Metadata is bounded by dialog count, endpoint count,
bytes, and expiry. Expired or evicted metadata can make later promotion unavailable.

By default all captured interfaces share observation domain zero: SIP on one
interface can admit media on another. Explicit domains separate overlapping local
observations, including registry ownership, inherited selection, TCP streams and
IP fragment reassembly. Domain configuration must agree with where signaling and
media are visible. Assigning them to different domains prevents correlation.
Configured call, endpoint-association and positive TCP-stream budgets are
partitioned across domain processors rather than multiplied. A positive budget too
small to assign a nonzero share is rejected at startup; zero TCP streams retains
its existing unlimited meaning.
Domain isolation is local capture attribution; central output grouping still uses
the original SIP Call-ID. Identical visible Call-IDs are not rewritten.

## Explicit restrictions and compatibility

The user-provided `--filter` predicate runs before every admission bypass. Explicit
`--udp-only`, `--sip-port`, and `--rtp-port-range` settings are also retained.
Automatically generated RTP ranges are not applied to learned endpoints. Thus a
selected SDP endpoint outside 10000–32768 can be captured unless an explicit
restriction excludes it. `--udp-only` excludes TCP signaling and ESP.

With no SIP-port constraint, TCP reassembly input and non-media UDP remain
available for arbitrary-port SIP discovery. A conservative RTP/RTCP header test
identifies packets eligible for dynamic media rejection. This is a capture-load
optimization; it does not promise rejection of every possible unrelated UDP
packet.

Fragments, bounded-parser unknown forms, deep IPv6 extension chains, VXLAN and
enabled ESP-NULL use counted packet-local compatibility admission where complete
endpoint inspection is unavailable. Non-initial fragments cannot supply ports.
Compatibility preserves the explicit base predicate and known protocol
restrictions, but can reduce selectivity. An unfamiliar packet never opens the
entire domain. VXLAN traffic containing ESP follows the same compatibility rule.

The current supported link type is Ethernet, including ordinary single/double
VLAN headers. Endpoint lookup works with hardware-stripped VLAN headers. Explicit
`vlan` capture expressions are rejected until offload-aware predicate composition
is supported. Linux cooked capture, including the usual `any` device, is rejected
when admission is enabled. Unsupported predicate instructions fail at startup;
they are not replaced with a broader predicate.

## Configuration

Only the two VoIP subcommands expose these flags:

| Flag                        | Default   | Meaning                                              |
| --------------------------- | --------- | ---------------------------------------------------- |
| `--rtp-ebpf`                | `false`   | Explicitly enable admission.                         |
| `--rtp-ebpf-mode`           | `enforce` | `enforce` or diagnostic `shadow`.                    |
| `--rtp-ebpf-failure-policy` | `open`    | Runtime update failure behavior: `open` or `closed`. |

Setting a mode or failure policy does not enable the feature. CLI values override
YAML, including an explicit `--rtp-ebpf=false`. Advanced settings live below
`hunter.voip.rtp_ebpf` or `tap.voip.rtp_ebpf`:

```yaml
tap:
  voip:
    rtp_ebpf:
      enabled: true
      mode: enforce
      failure_policy: open
      interface_domains:
        eth0: 1
        eth1: 1
        eth2: 2
      endpoint_capacity: 40000
      owner_capacity: 10000
      max_endpoints_per_owner: 32
      pending_dialog_capacity: 10000
      pending_endpoint_capacity: 40000
      pending_bytes: 8388608
      pending_ttl: 30s
      expiration_batch: 256
      retry_interval: 1s
      shadow_evidence_capacity: 1024
      missing_media_interval: 30s
```

Unassigned interfaces use domain zero. Domain IDs must be below 4096. Capacities
and durations must be positive. Endpoint capacity counts distinct map entries;
shared endpoints remain installed until their final eligible owner is removed.
Per-owner limits count RTP and separate RTCP endpoints. Pending metadata has
independent limits so unmatched call churn cannot grow memory without bound.
The controller separately bounds pending owner tokens by `pending_dialog_capacity`
across all domains. These tokens retain a selected lifetime while active owner
slots are full; endpoints remain in the authoritative call registry and are retried
without requiring another SDP message. They do not count as active owners or
retain packet payloads. Metadata and token pools each enforce their stated bounds.
These defaults are resource settings, not throughput or latency guarantees.

## Failure and diagnostic modes

Explicit enablement fails startup if required maps, program attachment, privileges,
link type or configuration cannot be supported. There is no automatic fallback to
broad capture or shadow mode. Capture readiness is reported only after every
requested interface has installed policy. Partial initialization is unwound.

| State           | Meaning                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------- |
| Disabled        | Existing capture; no eBPF admission resources.                                              |
| Initializing    | Required policy is not yet ready.                                                           |
| Enforcing       | Selected endpoint and independent-selector admission is active.                             |
| Shadow          | Explicit restrictions apply; dynamic rejection is observed but bypassed.                    |
| Degraded-open   | Affected domain bypasses dynamic media rejection after confirmed synchronization failure.   |
| Degraded-closed | Keep valid installed admissions while reporting missing or unsynchronized state.            |
| Recovery        | Reconcile the entire current endpoint and selector set before restoring normal mode.        |
| Control-failed  | A requested mode write failed; last confirmed mode and uncertainty are reported separately. |

Open is the default runtime failure policy. A separately preallocated control map
allows opening even when the endpoint map is full. If the control write itself
fails, status does not claim fail-open succeeded. Explicit restrictions and all
userspace authorization checks remain in force. Recovery includes additions,
deletions, selector changes and current ownership; one successful map update is
not sufficient evidence of recovery. Persistent failures can keep a domain degraded.
If even the bounded pending-owner pool is exhausted, the lost selection is marked
unknown and ordinary retries cannot establish completeness. Restart the enabled
capture after correcting capacity/traffic conditions; it must not silently declare
recovery from an incomplete owner set.

Status includes configured/effective modes, desired/installed generations,
occupancy, pending changes, update/control errors, compatibility decisions,
metadata eviction/expiry, and diagnostic evidence loss. Existing capture-drop
counters retain their meaning. Ordinary status does not expose endpoint addresses,
selector values, packet payloads or Call-IDs.

Shadow evidence is bounded and timing-sensitive. Distinguish expected rejection
before selection, packets during the selection-to-publication interval, and a
rejection after confirmed publication. Aggregate counters or a later map lookup
cannot prove an earlier packet decision. Live fingerprints can collide, samples
can duplicate, and events can be lost. Synthetic test packet identities supply
stronger evidence. Shadow also has a different load profile from enforcement.

Selected, answered calls without attributed media produce a diagnostic after the
configured interval. Installed endpoints and kernel-admitted candidates are
separate from final userspace-attributed media. Hold/inactive media, routing,
observation placement and NAT may explain missing media. This diagnostic does not
automatically widen capture.

## Build, startup, and verification

The loader requires Linux BPF socket programs and ring buffers (Linux 5.8 or later
feature set), plus permission to create maps/load programs and capture packets.
The privileged tests run in an isolated container. Capability restrictions,
security policy and kernel configuration can still prevent loading; initialization
returns the actual failure.

The pinned local gopacket extension owns attachment inside the libpcap binding.
It never extracts a private C pointer or closes a borrowed socket descriptor.
Ordinary builds consume embedded BPF objects and do not require clang. Generation
uses the recorded container toolchain:

```bash
internal/pkg/capture/ebpfadmission/toolchain.sh generate
make test-ebpf
```

`make test-ebpf` requires Docker and explicitly runs a disposable privileged
container with its own network namespace. It verifies real kernel decisions,
libpcap attachment, and command behavior. Default unprivileged tests report these
cases as not exercised. Compiler/container caches are ephemeral; generated source
and both endian objects are checked in. See the
[backend notes](../internal/pkg/capture/ebpfadmission/README.md) and
[binding patch provenance](../third_party/gopacket/LIPPYCAT_PATCH.md).

Enabled handles use immediate mode, attach a startup reject-all policy, drain
queued data, then activate the final program. Host-timestamp startup fencing also
rejects pre-activation frames. This deliberately permits startup packet loss;
clock adjustments can affect the timestamp boundary. The implementation rejects
unsupported ring-drain modes rather than declaring an unretired block empty.

libpcap remains a cgo dependency. Cgo is not single-threaded and does not disable
Go goroutines. This feature avoids unnecessary packet delivery and decoding; it
does not replace capture with native AF_PACKET or remove cgo across the project.
Performance measurements compare equivalent broad/shadow/enforce traffic and
record environment and compatibility passes. The 100 calls/s scenario is workload
context, not a new acceptance threshold.
