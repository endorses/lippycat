# Distributed media selection and capture continuity

Hunters can capture SIP and RTP on different interfaces or hosts. A processor can
select a call from SIP, then publish temporary media rules to every eligible
hunter in the same observation domain. A hunter that never saw the INVITE can
capture that call's RTP and recognize validated later signalling. This works when
the packet route changes without an endpoint change or another SIP offer.

The same components run inside a tap: its local capture source subscribes to its
own processor's publisher in process. No loopback gRPC connection is needed.
Ordinary capture, packet outputs and optional LI consumers use these features.

## Defaults and independent choices

| Choice | Default | Alternatives |
| --- | --- | --- |
| Managed-filter distribution | `distributed` | `local_only` keeps matching on the processor/tap |
| SIP forwarding | `matched` | `all` forwards eligible candidate SIP; `none` suppresses SIP export |
| Media selection | `local` | `processor` requires a current temporary rule |
| Cross-hunter packet duplicate suppression | Disabled | Explicitly enable bounded per-consumer suppression |

`--signalling-policy` and `--media-policy` are independent on `hunt voip` and
`tap voip`. SIP is still parsed for local state when SIP export is disabled.
`matched` can forward signalling already associated with a valid processor rule;
it does not automatically forward every new call. `all` is the explicit choice
when the processor must discover and select new calls whose identity filters
remain central. `none` with processor-selected media needs another eligible
source to supply the signalling that establishes the rules.

Explicit BPF expressions, SIP-port restrictions, RTP-port ranges and transport
restrictions still apply. Processor-selected media has no implicit legacy
10000–32768 RTP range; an explicitly configured range remains a restriction.
Do not use a capture restriction that excludes the candidate SIP or advertised
media endpoints you need. Kernel admission is a candidate check; userspace still
verifies exact current endpoint ownership, source domain and call lifetime.
Existing eBPF startup/runtime failure policy is unchanged.

## Keep an identity filter local

Enable `processor.voip.media_rules.enabled` (or the tap equivalent) for central
SIP call selection. Central matching evaluates current enabled SIP user/URI,
phone-number, packet IP/CIDR and exact case-sensitive Call-ID selectors against
the authenticated source scope; hunter-supplied match IDs do not replace that
check.

```bash
lc set filter -P processor.example.test:55555 --tls-ca ca.crt \
  --tls-cert operator.crt --tls-key operator.key \
  --type sip_user --pattern alice --id alice-selection \
  --distribution-scope local_only

lc show filter -P processor.example.test:55555 --tls-ca ca.crt \
  --tls-cert operator.crt --tls-key operator.key \
  --id alice-selection
```

The equivalent managed-filter entry is:

```yaml
filters:
  - id: alice-selection
    type: sip_user
    pattern: alice
    enabled: true
    distribution_scope: local_only
```

An omitted scope means `distributed`. `target_hunters` retains its existing
meaning for distributed filters: an empty list means all compatible hunters.
Local-only filters ignore that list for central matching. List/show JSON exposes
the scope; persisted default-distributed entries may omit the field.

The server omits local-only filters from hunter queries, initial snapshots and
live updates. Changing a distributed filter to local-only sends withdrawals of
its old copies, including to older hunters. The central filter remains stored
and active. Administrative list/show queries can still inspect it.

Signed shared capture snapshots are exported intact to hunters, so they reject
local-only entries. In a shared-policy deployment, store independent local-only
filters outside the reserved shared namespace. Do not put a private pattern into
a signed capture snapshot and rely on the receiving hunter to hide it.

## Processor and two hunters

Use an explicit observation-domain mapping. Here both capture interfaces observe
the same address realm, central domain `7`, while their local domain numbers are
`10` and `20`. Unrelated networks that reuse addresses need different central
domains. A mapping authorizes neither a peer nor an interception task.

Save as `processor.yaml`:

```yaml
processor:
  voip:
    media_rules:
      enabled: true
      rule_ttl: 30s
      max_lifetime: 5m
      trailing_grace: 5s
      call_timeout: 30m
      sources:
        - hunter_id: edge-a
          interface: eth0
          domain: 7
          hunter_domain: 10
        - hunter_id: edge-b
          interface: eth1
          domain: 7
          hunter_domain: 20
  packet_dedup:
    enabled: false
    window: 2s
    max_entries: 10000
    max_bytes: 33554432
```

Start the processor with a stable ID. Its certificate must identify the configured
processor ID, and hunter certificates must identify their registered hunter IDs.
Normal TLS server-hostname verification also applies:

```bash
lc --config processor.yaml process --id processor-1 --listen :55555 \
  --tls-cert processor.crt --tls-key processor.key --tls-ca ca.crt \
  --tls-client-auth
```

Save the first hunter configuration as `edge-a.yaml`:

```yaml
hunter:
  voip:
    signalling_policy: all
    media_policy: processor
    interface_domains:
      eth0: 10
    media_rules:
      enabled: true
      processor_id: processor-1
      clock_uncertainty: 0s
```

```bash
sudo lc --config edge-a.yaml hunt voip --id edge-a -i eth0 \
  --processor processor.example.test:55555 --tls-ca ca.crt \
  --tls-cert edge-a.crt --tls-key edge-a.key
```

For `edge-b`, use `eth1: 20`, `--id edge-b`, `-i eth1`, and its own certificate/key.
`--signalling-policy all --media-policy processor` can override the corresponding
YAML policy choices. Processor-selected hunter media requires verified mutual TLS
and the configured processor identity; insecure transport and skipped server
verification cannot establish media-control authority.

If the existing eBPF path is also enabled, its
`hunter.voip.rtp_ebpf.interface_domains` must agree with
`hunter.voip.interface_domains`. The independent interface map also works without
eBPF. Domain mappings use concrete captured interface names.

After installing the local-only selection filter, an INVITE observed at `edge-a`
can establish media rules for both hunters. For example, RTP from
`192.0.2.10:40000` to `198.51.100.20:50000` can move to `edge-b` unchanged. The new
hunter uses its current rule without waiting for another INVITE or SDP update.
A later BYE through `edge-b` must match validated dialog/transaction evidence;
Call-ID equality alone is insufficient. Withdrawal and the configured trailing
media grace then end capture eligibility.

## Standalone tap

Use the same central selection and publisher with the tap's actual local source
ID, `<tap-id>-local`. Save as `tap-media.yaml`:

```yaml
tap:
  voip:
    signalling_policy: all
    media_policy: processor
    interface_domains:
      eth0: 10
    media_rules:
      enabled: true
      sources:
        - hunter_id: tap-1-local
          interface: eth0
          domain: 7
          hunter_domain: 10
  packet_dedup:
    enabled: false
```

```bash
sudo lc --config tap-media.yaml tap voip --id tap-1 -i eth0 \
  --signalling-policy all --media-policy processor \
  --tls-cert tap.crt --tls-key tap.key
```

The local subscription uses the same bounded snapshots, exact endpoint ownership
and expiry checks as a hunter subscription. The tap's management listener keeps
its ordinary TLS configuration; local media control does not depend on that
listener or require an upstream processor. Set managed filters through the tap's
existing management API.

## Rule lifetime, reconnect and limits

Temporary media rules are separate from durable managed filters. Each carries
processor/session identity, a monotonic revision, call lifetime, source/domain
scope, endpoints, current selection and absolute validity times. RTP and RTCP
ownership remain exact even if a kernel candidate key is broader.

A fresh, complete snapshot becomes effective atomically. Broken/oversized partial
snapshots do not publish a partial selection. Stale revisions, wrong issuers,
wrong domains, ambiguous endpoint ownership and expired rules do not authorize
capture. A reconnect requests current authoritative state; it does not extend an
old rule's deadline. The active processor may explicitly renew current selected
calls. Withdrawal, changed selection, BYE/CANCEL handling and call timeout remove
eligibility, with the configured trailing grace where applicable.

The shared `*.voip.media_rules` bounds are:

| Key | Default |
| --- | --- |
| `rule_ttl` | `30s` |
| `max_lifetime` | `5m` |
| `max_rules` | `10000` |
| `max_bytes` | `33554432` |
| `max_endpoints` | `40000` |
| `max_endpoints_per_rule` | `32` |
| `max_subscribers` | `256` |
| `subscription_buffer` | `64` |
| `max_message_bytes` | `1048576` |
| `max_snapshot_bytes` | `33554432` |
| `clock_uncertainty` | `0s` |

`max_lifetime` bounds one issued validity interval, not the total duration of an
actively renewed call. Processor/tap publication additionally uses `trailing_grace: 5s` and
`call_timeout: 30m`. Choose realistic clock uncertainty for the deployment; it
must remain below half the rule TTL. These defaults bound resources and leases;
they are configurable operational settings, not latency or throughput guarantees.

Existing call buffers, capture queues and reliable packet spools retain their
configured limits and receipt semantics. A retained packet or replayed historical
SIP message cannot refresh current capture authority merely by arriving again.
Reliable-ingress current-capture proof is volatile: reconnect backlog and
restart recovery do not recreate permission to rearm current media rules.
Original capture node/interface/time and explicit observation-domain provenance
survive forwarding and storage; receivers validate domain claims against their
configured mappings. Temporary media rules do not create a durable call-history
or packet-history index. See [reliable forwarding](PROCESSOR_FAILOVER.md) for existing storage,
failover and offline-authority requirements.

## Optional cross-hunter packet duplicate suppression

Enable `processor.packet_dedup.enabled` or `tap.packet_dedup.enabled`. The window,
entry count and charged-byte limits default to `2s`, `10000` and `33554432`.
Suppression requires distinct authenticated capture origins and an explicit common
observation-domain mapping. Same-source repeats remain eligible. Unmapped or
untrusted sources retain their packets.

Supported comparisons use complete nonfragmented IPv4 without options, or IPv6
without extension headers. They strip Ethernet/VLAN framing and normalize the
hop count and IPv4 header checksum, while verifying the remaining packet bytes.
UDP needs a nonzero IPv4 packet ID or usable RTP/RTCP sender-report identity.
IPv4 ICMP echo needs a nonzero packet ID. TCP, other unsupported forms and
ambiguous repeat histories are retained rather than inferred from payload
similarity. Changed protocol identity/content and independent observation domains
remain distinct.

Each consumer owns its own decision: unified PCAP; each call incarnation's PCAP;
rotating PCAP; normalized event analysis; call aggregation/correlation; DNS
aggregation; each eligible monitoring subscriber; upstream packet forwarding;
and virtual-interface injection. Monitor hunter/BPF eligibility precedes the
claim. LI tasks have separate authorized consumer contexts. A successful queue
admission or synchronous processing/write commits only that owner's claim;
rejection releases it. Queue admission is not a guarantee of eventual I/O or
network delivery. Event-runtime fan-out to its asynchronous sinks is unchanged.

Concurrent ownership that has not yet accepted a copy is retained without waiting.
Capacity pressure, unsupported/ambiguous packets and observations outside the
window are also retained and counted as reduced coverage. The byte budget counts
charged cache storage, not process RSS. Raw ingress counters and reliable receipt/
retry accounting remain unchanged. This feature does not promise exactly-once
output or suppress long-delayed replay beyond its configured window.

## Status and troubleshooting

```bash
lc show status -P processor.example.test:55555 --tls-ca ca.crt \
  --tls-cert operator.crt --tls-key operator.key
lc show hunter --id edge-a -P processor.example.test:55555 --tls-ca ca.crt \
  --tls-cert operator.crt --tls-key operator.key
lc list filters --hunter edge-a -P processor.example.test:55555 --tls-ca ca.crt \
  --tls-cert operator.crt --tls-key operator.key
```

Processor status includes `media_rules` when publication is enabled. Its fields
are `enabled`, `ready`, `generation`, `revision`, `sequence`, `rules`, `endpoints`,
`bytes`, `subscribers`, `expired`, `stale_updates`, `resyncs`, `active_calls` and
`application_failed`. Hunter `stats.media_rules` reports applied generation,
revision, readiness and rule/endpoint counts. A pending report has `enabled: true`
and false/omitted `ready`; `application_failed` indicates a failed application,
without exposing raw error text or selectors. Zero/false fields may be omitted.

Optional `packet_duplicates` status exposes `attempts`, `committed`, `duplicates`,
`in_flight`, `repeats_retained`, `unsupported_retained`, `ambiguous_retained`,
`capacity_retained`, `outside_window_retained`, `aborted`, `entries`, `contributors`
and `bytes`. Attempts and duplicates count independent consumer decisions, not
raw received packets. Retention counters describe reduced suppression coverage;
`entries`, `contributors` and `bytes` describe current bounded cache occupancy.
These summaries do not expose call IDs, selection patterns or packet addresses.

For missing media, compare configured/certificate node identities, actual capture
interface names and both sides' domain numbers, then check snapshot readiness,
rule expiry, clock uncertainty and application failures. Verify that candidate SIP
reaches central selection and that capture restrictions permit the media ports.
Hunter-filtered lists should omit local-only selectors; administrative list/show
queries should retain them. Check existing capture/output queue-drop counters
separately: successful rule application and duplicate suppression do not prove
lossless capture or delivery.

## LI central task selection

Set root-level `li.task_filter_distribution_scope: local_only` (default `distributed`) on the LI processor or tap to retain task-created identity filters and their derived selectors centrally, including after modification and recovery. The equivalent flag is `--li-task-filter-distribution-scope local_only`. Administrative queries retain their authorized visibility; hunter filters, signed policies and media rules omit private patterns and guessable selector digests.

Central selection exports a separate signed `MEDIA` grant with an opaque reference/revision, issuer, source/domain scope and finite validity. A hunter needs both that grant and the exact current authenticated media rule, including the call incarnation and unambiguous RTP/RTCP endpoints. A grant ID alone, a kernel endpoint hit or an empty filter list does not authorize capture. Media-only grants do not authorize SIP or arbitrary UDP. Initial SIP must arrive through an independently authorized observation path, such as trusted tap-local capture; remote hunters can use `signalling_policy: none` with `media_policy: processor`. LI-owned capture still rejects `signalling_policy: all`.

Grant-bearing signed policies use protocol version 2; ordinary filter policies retain version 1 and historical version-1 evidence remains readable. Upgrade participating peers before enabling grant-based capture. Unsupported peers fail explicitly and never fall back to distributing private patterns. Packets retain the original signed policy and exact signed media-rule proof; historical replay checks capture-time authority and current delivery authorization without renewing capture rules.

Include every eligible source explicitly in `li.handover.source_ids`. Include
`tap-1-local` if the tap's own media capture participates, as well as remote IDs.
Every source also needs a concrete `*.voip.media_rules.sources` mapping with its
actual interface and local observation domain; the mapping's `domain` joins the
central address realm and does not replace the exported local capture domain.
The following tap fragment supplements the protected LI/shared-policy and reliable
raw setup in [the failover guide](PROCESSOR_FAILOVER.md#optional-li-handover):

```yaml
li:
  task_filter_distribution_scope: local_only
  delivery:
    capture_source_metadata: true
  handover:
    enabled: true
    lease_duration: 2m
    allow_offline: false
    clock_uncertainty: 1s
    source_ids: [tap-1-local, edge-a, edge-b]
tap:
  voip:
    signalling_policy: matched
    media_policy: processor
    interface_domains:
      eth0: 10
    media_rules:
      enabled: true
      sources:
        - hunter_id: tap-1-local
          interface: eth0
          domain: 7
          hunter_domain: 10
        - hunter_id: edge-a
          interface: eth0
          domain: 7
          hunter_domain: 20
        - hunter_id: edge-b
          interface: eth1
          domain: 7
          hunter_domain: 30
```

Provision the LI task through X1. Observe eligible SIP on the trusted local tap
path; the processor's real task filters select the call and publish grants/rules.
Configure each remote hunter with its corresponding interface-domain number,
`signalling_policy: none`, `media_policy: processor`, the stable tap processor ID,
verified mTLS, `filter_policy.owner: li`, encrypted policy/raw stores and reliable
raw packet delivery. Initial SIP and media-only capture authority are separate.
An otherwise identical separate processor needs an authorized SIP source; a
media-only grant cannot bootstrap signalling observation. Keep `allow_offline`
false unless bounded disconnected capture is explicitly required. Lease expiry,
source exclusion and withdrawal reject new capture independently of delivery.

## Receiver-visible capture source

Enable root-level `li.delivery.capture_source_metadata: true` or `--li-delivery-capture-source-metadata` only when every configured MDF destination is intended to consume the private extension. The default is `false`, preserving existing wire output. New enabled products require actual nonempty node and interface/source identifiers before sequence allocation. Capture time keeps its existing timestamp field and missing-time behavior; unknown observation domains remain distinct from known domain zero.

The extension uses the existing `AttrProprietary` container with the owner envelope required by TS 103 221-2 §5.3.5. The value begins with one unsigned byte containing owner length `9` (`0x09`), followed by the ASCII owner `lippy.cat`, without a NUL terminator. The owner is a fixed lowercase hostname whose labels follow RFC 1123. The owner-defined body carries one-byte source subtype `1`, version `2` and flags (bit zero means domain known), followed by node length, interface length, domain, node and interface. Both lengths are big-endian unsigned 16-bit values, domain is unsigned 32-bit, and identifiers are UTF-8 with a 4096-byte bound each. Unknown domain uses zero; the existing unsigned 16-bit TLV length bound still applies.

`x2x3.DecodeProductCaptureSource` reports unavailable for an absent attribute, an empty, truncated or invalid hostname owner, an unrelated owner, or an unknown subtype. A matching owner without a subtype is an error. For source subtype `1`, unsupported versions, invalid flags, lengths, UTF-8, trailing bytes and duplicate capture-source attributes are rejected. PDU and TLV boundary validation remains strict even when the owner is ignored. SIP X2, RTP X3 and the RADIUS source adapter use the same extension; RADIUS has no observation-domain fact and exports it as unknown.

The initial draft format (`lippycat.capture_source` plus NUL, subtype `1`, version `1`) is no longer emitted or decoded as capture-source metadata. Journal recovery and approved replay preserve already encoded bytes unchanged, so existing draft-format records remain in that format when replayed.

The configured processor/tap identity continues to define delivery context and sequencing. Capture-source changes do not enter the sequence key. The attribute is frozen before deferred RTP ordering and destination fan-out; destinations receive the same encoded source bytes and sequence. Journals retain the exact encoded product through recovery and approved replay. Enabling the setting never synthesizes source metadata into already encoded legacy records, and existing task, expiry, revocation and replay checks remain required.

Late RTP and rejected outputs can still cause disorder or sequence gaps; destination
fan-out retains its existing non-atomic admission semantics. Keep processor identity
stable across restart and follow [LI recovery procedures](LI_INTEGRATION.md).

## Measure the selection path

The duplicate window bounds observation age and retained comparison evidence, not the total duration of source overlap. A long overlap can suppress corresponding copies that arrive promptly; delayed copies and replay outside the window remain eligible. Measure signalling observation, central selection, rule activation and first admitted media separately, including missing early media and disconnected expiry. These measurements describe the actual control path and do not imply a one-round-trip or fixed packet-loss guarantee.
