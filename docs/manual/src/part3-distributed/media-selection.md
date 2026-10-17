# Distributed Media Selection {#distributed-media-selection}

A processor can select a call from SIP observed by one hunter and publish temporary media rules to other eligible hunters. A hunter that never saw the INVITE can then capture the existing RTP flow, even when the route changes without new SIP or a change to the media endpoints. A tap uses the same publisher and local subscription in process, without loopback gRPC.

## Choose signalling and media independently {#media-policy-choices}

`hunt voip` and `tap voip` accept `--signalling-policy matched|all|none` and `--media-policy local|processor`. Defaults remain `matched` and `local`. SIP export can be disabled while SIP parsing still maintains local call state. Explicit `all` forwards eligible candidate SIP regardless of local identity matching; it does not select all media or bypass existing BPF, port or transport restrictions.

Use `all` when the processor must discover new calls whose identity patterns remain central. `matched` can also forward later signalling associated with a current validated processor rule. `none` with processor-selected media requires another eligible source to establish the call. A later BYE through a hunter that missed the INVITE needs validated dialog/transaction evidence; Call-ID equality alone is insufficient.

## Keep managed selectors local {#media-local-filters}

Create or update an ordinary managed filter with `--distribution-scope local_only`, or set `distribution_scope: local_only` in its YAML entry. The omitted/default scope remains `distributed`. `target_hunters` still means all compatible hunters when empty in distributed scope; local-only matching ignores that list. Administrative list/show output exposes the scope.

<!-- i18n:skip -->

```bash
lc set filter -P processor.example.test:55555 --tls-ca ca.crt \
  --tls-cert operator.crt --tls-key operator.key \
  --id alice-selection --type sip_user --pattern alice \
  --distribution-scope local_only
```

The server omits local-only patterns from hunter queries, snapshots and live updates, including for older peers. Changing scope withdraws old distributed copies while keeping central matching active. Signed shared capture snapshots reject local-only entries because those snapshots leave the processor intact; independent local filters must remain outside the reserved shared namespace.

## Map capture domains explicitly {#media-source-domains}

Configure publication under `processor.voip.media_rules`, hunter policies/subscription under `hunter.voip`, and tap equivalents under `tap.voip`. Every source mapping names a hunter and concrete captured interface, joins it to a central observation domain, and specifies that hunter's local domain number. Distinct address realms that reuse IP addresses need different central domains. Mapping a source is not authentication or output authorization.

The following processor fragment joins two capture interfaces to one observation domain. The hunters must configure the matching local numbers in `hunter.voip.interface_domains`: `eth0: 10` on `edge-a` and `eth1: 20` on `edge-b`. Any existing eBPF interface-domain map must agree; this independent map also works without eBPF.

<!-- i18n:skip -->

```yaml
processor:
  voip:
    media_rules:
      enabled: true
      rule_ttl: 30s
      sources:
        - hunter_id: edge-a
          interface: eth0
          domain: 7
          hunter_domain: 10
        - hunter_id: edge-b
          interface: eth1
          domain: 7
          hunter_domain: 20
hunter:
  voip:
    signalling_policy: all
    media_policy: processor
    interface_domains:
      eth0: 10
    media_rules:
      processor_id: processor-1
```

Set the processor's stable `--id processor-1` and use verified mutual TLS for remote rules. The processor certificate must identify that processor ID as well as satisfy normal server-hostname verification; hunter certificates must identify their registered IDs. Insecure or unverified transport does not establish media-control authority. A tap maps its own source as `<tap-id>-local` in `tap.voip.media_rules.sources` and uses its local subscription without an upstream connection.

## Expiry and bounded operation {#media-expiry}

Temporary media rules carry processor/session identity, revisions, call lifetime, current selection, endpoints, source/domain scope and absolute deadlines. A complete snapshot becomes effective atomically. Partial snapshots, stale updates, ambiguous endpoint ownership, wrong domains and expired rules do not authorize capture. Reconnection requests current authoritative state and never extends an old deadline by itself; the active processor may explicitly renew current selected calls.

Defaults are a `30s` rule TTL, `5m` maximum rule lifetime, `10000` rules, `33554432` charged bytes and `40000` endpoints, with at most `32` endpoints per rule. Subscription defaults are `256` subscribers and `64` queued updates; message and snapshot bounds are `1048576` and `33554432` bytes. Clock uncertainty defaults to `0s` and must remain below half the TTL. Processor/tap publication uses a `5s` trailing grace and `30m` call timeout. These are configurable resource/lease limits, not performance guarantees.

Explicit capture restrictions and the existing eBPF failure policy remain in force. Processor-selected media has no implicit legacy RTP port range. Existing capture/call buffers and reliable spools retain their configured bounds and receipt semantics; historical replay does not refresh current capture authority merely by arriving again. See [Failover and Reliable Delivery](processor-failover.md).

## Optional duplicate suppression {#media-packet-duplicates}

Enable `processor.packet_dedup.enabled` or `tap.packet_dedup.enabled` explicitly; suppression is disabled by default. Configurable defaults are a `2s` window, `10000` entries and `33554432` charged bytes. Distinct authenticated capture origins and an explicit common domain are required. Same-source repeats, unknown domains, unsupported packets, ambiguous history, concurrent unaccepted ownership, capacity pressure and observations outside the window retain their packets and reduce reported coverage.

Comparisons preserve protocol identity and verify content while excluding Ethernet/VLAN framing, hop count and the IPv4 header checksum. Supported forms are complete nonfragmented IPv4 without options and IPv6 without extension headers: UDP needs a nonzero IPv4 packet ID or usable RTP/RTCP sender-report identity; IPv4 ICMP echo needs a nonzero packet ID. TCP is retained because byte equality cannot prove that a packet is not a legitimate retransmission.

Each owner has an independent decision: unified PCAP, each call incarnation's PCAP, rotating PCAP, normalized event analysis, call aggregation/correlation, DNS aggregation, each eligible monitoring subscriber, upstream packet forwarding and virtual-interface injection. Monitor hunter/BPF eligibility precedes suppression. A successful synchronous operation or queue admission commits only that owner's claim; rejection releases it. Queue admission does not guarantee eventual I/O or network delivery. Event-runtime sink fan-out, raw ingress counts and reliable receipt/retry accounting remain unchanged. This is not exactly-once output or a durable global replay index.

## Status and troubleshooting {#media-status}

`lc show status` exposes enabled processor publication under `media_rules`: readiness, generation/revision/sequence, rule/endpoint/byte/subscriber counts, `expired`, `stale_updates`, `resyncs`, `active_calls` and `application_failed`. `lc show hunter --id edge-a` exposes applied state under `stats.media_rules`; a pending report has `enabled: true` and false/omitted `ready`. Zero/false fields may be omitted. Summaries contain no call IDs, selectors or raw application error text.

Optional `packet_duplicates` status exposes `attempts`, `committed`, `duplicates`, `in_flight`, `repeats_retained`, `unsupported_retained`, `ambiguous_retained`, `capacity_retained`, `outside_window_retained`, `aborted`, `entries`, `contributors` and `bytes`. Attempts count independent consumer decisions rather than raw packets; retention counters describe reduced suppression coverage, while entry/contributor/byte gauges describe bounded cache occupancy. Investigate capture/output queue drops separately: readiness and suppression do not prove lossless delivery.

For missing media, verify certificate/node identity, concrete interfaces, domain mappings, candidate SIP forwarding, complete snapshot readiness, clock uncertainty, expiry and capture restrictions. Original capture node/interface/time and explicit observation-domain provenance survive forwarding/storage and are checked against configured mappings. Reliable-ingress current-capture proof is volatile; reconnect backlog and restart recovery cannot recreate authority to rearm current rules. Historical evidence remains separate from current capture permission.

## LI compatibility {#media-li-compatibility}

LI consumers use the same general call association, source provenance, expiry and independent consumer boundaries while preserving existing task authorization, revocation, capture grants, replay approval and protected storage. A media rule is not independent interception authorization. LI-generated filters keep their existing distributed default; central media rules do not automatically hide their identity patterns. LI-owned reliable VoIP capture requires verified mTLS, encrypted origin spool storage and a current signed finite capture policy. It supports `matched` or `none`; `all` is rejected because exporting unselected signalling would exceed the capture grant. Processor media rules alone do not grant capture authority.

Configured processor/tap identity supplies a stable live delivery context across hunter changes, while original capture node/interface/time remain source metadata. Production output preserves bounded RTP reordering and assigns sequence numbers once before destination fan-out in ordinary and persistent paths. Late packets and rejected outputs can still cause disorder or gaps. Already encoded durable records and checkpoints retain their original bytes/context; an upgraded deployment may replay old contexts alongside the new live context while its approved backlog drains. No new identity mode or automatic journal relabelling is introduced.
