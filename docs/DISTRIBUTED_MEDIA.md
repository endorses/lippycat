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

## LI integration

LI builds consume the same general selection, source provenance, expiry and
per-consumer duplicate boundaries. A media rule associates traffic with a selected
call; it is not independent interception authorization. Existing task validation,
expiry, revocation, capture grants, replay approvals and protected storage remain
necessary. LI-generated identity filters keep their existing distributed default;
enabling central media rules does not automatically hide their patterns from
hunters. LI-owned reliable VoIP capture requires verified mTLS, encrypted origin
spool storage and a current signed finite capture policy. It supports `matched`
or `none`; `all` is rejected because exporting unselected signalling would exceed
the capture grant. Processor media rules alone do not grant capture authority.

Configured processor/tap identity now supplies the stable live delivery context;
switching capture hunters does not reset that context. Original capture node,
interface and timestamp remain source metadata. No new identity mode is needed.
Production delivery preserves bounded RTP reordering, then assigns the output
sequence once before destination fan-out in both ordinary and persistent paths.
Late packets can still arrive outside the reorder window, and output rejection
can still produce gaps; fan-out is not atomic across destinations.

Upgrading does not rewrite or relabel already encoded durable records or their
checkpoints. Their original bytes and delivery contexts replay unchanged after
existing authorization checks. New live products use the configured processor
context, so old capture-node contexts and the stable live context can coexist
while an approved backlog drains. Keep processor identity stable across restarts
and follow [LI recovery procedures](LI_INTEGRATION.md) for journal migration.
