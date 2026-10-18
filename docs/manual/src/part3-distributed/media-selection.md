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

Set root-level `li.task_filter_distribution_scope: local_only` (default `distributed`) on the LI processor or tap to retain task-created identity filters and their derived selectors centrally, including after modification and recovery. The equivalent flag is `--li-task-filter-distribution-scope local_only`. Administrative queries retain their authorized visibility; hunter filters, signed policies and media rules omit private patterns and guessable selector digests.

Central selection exports a separate signed `MEDIA` grant with an opaque reference/revision, issuer, source/domain scope and finite validity. A hunter needs both that grant and the exact current authenticated media rule, including the call incarnation and unambiguous RTP/RTCP endpoints. A grant ID alone, a kernel endpoint hit or an empty filter list does not authorize capture. Media-only grants do not authorize SIP or arbitrary UDP. Initial SIP must arrive through an independently authorized observation path, such as trusted tap-local capture; remote hunters can use `signalling_policy: none` with `media_policy: processor`. LI-owned capture still rejects `signalling_policy: all`.

Grant-bearing signed policies use protocol version 2; ordinary filter policies retain version 1 and historical version-1 evidence remains readable. Upgrade participating peers before enabling grant-based capture. Unsupported peers fail explicitly and never fall back to distributing private patterns. Packets retain the original signed policy and exact signed media-rule proof; historical replay checks capture-time authority and current delivery authorization without renewing capture rules.

Include every eligible source in `li.handover.source_ids`, including `<tap-id>-local` when its local media participates. Each source needs a concrete `*.voip.media_rules.sources` entry with `hunter_id`, `interface`, central `domain` and local `hunter_domain`. Remote hunters can capture selected media without seeing INVITE; initial SIP must come from a separate authorized path. Keep the stable processor identity, verified mTLS, encrypted policy/raw stores and reliable forwarding required by the LI-owned profile.

## Receiver-visible capture source {#media-capture-source}

Enable root-level `li.delivery.capture_source_metadata: true` or `--li-delivery-capture-source-metadata` only when every configured MDF destination is intended to consume the private extension. The default is `false`, preserving existing wire output. New enabled products require actual nonempty node and interface/source identifiers before sequence allocation. Capture time keeps its existing timestamp field and missing-time behavior; unknown observation domains remain distinct from known domain zero.

The extension uses the existing `AttrProprietary` container and namespace `lippycat.capture_source`, not a new standard identifier. Version 1 carries namespace plus NUL, source subtype `1`, version `1`, flags (bit zero means domain known), node length, interface length, domain, node and interface. Lengths are big-endian unsigned 16-bit values, domain is unsigned 32-bit, and identifiers are UTF-8 with a 4096-byte bound each. Unknown domain uses zero; invalid flags, lengths, UTF-8, trailing bytes, duplicate recognized values and unsupported versions are rejected. `x2x3.DecodeProductCaptureSource` reads live or journaled product and reports unavailable for legacy absence or unrelated proprietary attributes. SIP X2, RTP X3 and the RADIUS source adapter use the same extension; RADIUS has no observation-domain fact and exports it as unknown.

The configured processor/tap identity continues to define delivery context and sequencing. Capture-source changes do not enter the sequence key. The attribute is frozen before deferred RTP ordering and destination fan-out; destinations receive the same encoded source bytes and sequence. Journals retain the exact encoded product through recovery and approved replay. Enabling the setting never synthesizes source metadata into already encoded legacy records, and existing task, expiry, revocation and replay checks remain required.

## Measure the selection path {#media-selection-measurement}

The duplicate window bounds observation age and retained comparison evidence, not the total duration of source overlap. A long overlap can suppress corresponding copies that arrive promptly; delayed copies and replay outside the window remain eligible. Measure signalling observation, central selection, rule activation and first admitted media separately, including missing early media and disconnected expiry. These measurements describe the actual control path and do not imply a one-round-trip or fixed packet-loss guarantee.
