# Shared RADIUS decoding, matching and association

This package implements Phases 1–2 of the
[RADIUS plan](../../../docs/plans/radius-poi-implementation.md): validation,
owned observations, exact predicates and bounded transaction association.
Capture ingress wiring, observation transport and X2 delivery remain later work. Observational decoding does not authenticate RADIUS
Authenticators or prove subscriber ownership.

## Pinned gopacket audit

Audited the locally installed source of `github.com/google/gopacket v1.1.19`, as
pinned in `go.mod`, on 2026-09-09. Relevant source locations are
`layers/ports.go` (the UDP registration table) and `layers/radius.go`
(`RADIUS.DecodeFromBytes`, `decodeRADIUS` and `RADIUS.Payload`).

| Upstream behavior                                                                                                  | Shared decoder treatment                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Only UDP 1812 is registered automatically.                                                                         | Explicitly invoke the RADIUS payload decoder after ingress selects authentication, accounting or configured ports.                                                 |
| Header and outer AVP lengths are checked, including the 20–4096 declared length bounds.                            | Retain these checks through a fresh `layers.RADIUS.DecodeFromBytes` call.                                                                                          |
| Padding sets truncation feedback; a total payload above 4096 is rejected even if declared message length is valid. | Validate declared length and pass only those bytes to gopacket. Packet outputs retain their complete captured storage separately.                                  |
| `BaseLayer.Contents` borrows the supplied buffer.                                                                  | Copy the bounded message before decoding.                                                                                                                          |
| AVPs with length 2 are omitted from `Attributes`.                                                                  | Build the ordered attribute view from the fully validated raw message, retaining empty, unknown and repeated AVPs.                                                 |
| VSA contents and message code support are not validated.                                                           | Validate vendor headers, every vendor 3561 sub-attribute, supported circuit lengths, NAS address lengths and all six supported codes before returning any message. |
| `Payload()` contains concatenated EAP-Message values.                                                              | Preserve the original RADIUS message in `Message.Raw`; never use the application-layer payload as raw RADIUS.                                                      |

The wrapper never reconstructs original message bytes from gopacket fields.
Unknown vendors remain opaque after vendor-header validation, because their
inner formats need not use the DSL Forum type/length representation. Vendor
headers require a zero high Vendor-Id octet and at least one vendor-data octet.
Vendor 3561 containers validate all inner boundaries, including unknown types;
Agent-Circuit-Id values require 1–63 bytes. NAS-IP-Address and NAS-IPv6-Address
require exactly 4 and 16 value bytes, respectively.

## Ownership and error boundary

`Decode` accepts a complete UDP payload and returns either a fully validated
message or a nil message plus `ErrMalformed`/`ErrUnsupported` (use `errors.Is`).
Structural validation precedes unsupported-code classification. It never
returns partial attributes, including an early User-Name followed by a malformed
attribute. The packet ingress must reject fragments and truncated IP/UDP
datagrams before invoking it. No shared secret or identity matching is involved.

`Message.Raw`, AVP values and vendor values share storage owned by the returned
message; none alias the capture input. These fields must be treated as immutable
after publication. An asynchronous consumer that needs mutable fields must use
its own deep copy. Retained packet storage is separately owned and includes
network encapsulation and padding. Shared types do not import LI implementation
types or confer authorization.

The pure decoder never increments counters. The first observation ingress owns
one validation outcome per attempt. Downstream validation and cloning must not
increment origin counters. Association outcomes and counters are separately
owned by the correlator; sinks and LI admission own their respective
delivery and rejection counters.

`DecodePacket` accepts original captured bytes, link type, capture metadata and
origin scope. It validates IP/UDP boundaries and configured service ports before
calling `Decode`. IPv4 fragments and IPv6 Fragment headers (including atomic
fragments) are classified before UDP validation, without reassembly. Rejected
observations retain owned packet bytes and capture diagnostics, but no message,
NAS identities or attribution. Valid observations separate transport endpoints
from NAS attributes and start with association status `unprocessed`.

`NewIngress` creates a fresh unpredictable 128-bit capture epoch. Its concurrent
`Observe` method assigns monotonically increasing 64-bit observation IDs and
counts exactly one validation outcome. Sequence exhaustion fails without reuse.
Create a new ingress after source reopen, capture gaps or reconnect; retain old
scope on queued observations. Scope fields are caller-supplied provenance, not
proof of authenticated origin or authorization.

The model declares request identities, association statuses and separate direct
and inherited criterion groups with filter revisions and task generations.
Matching and association are separate from decoding: decoding cannot fabricate
an unmatched/ambiguous decision or inherited evidence. `Observation.Clone` deeply
copies packet, message, NAS and evidence storage for mutable asynchronous users.
All these shared contracts live in this non-LI package; display/protobuf adapters
in `types`/`protocolmeta` and command capability registration in `protocolcatalog`
remain deferred to their integration phases so they do not advertise unavailable
RADIUS processing or filtering.

## Validation

```bash
GOCACHE=/tmp/lippycat-go-cache go test ./internal/pkg/radius -count=1
GOCACHE=/tmp/lippycat-go-cache go test ./internal/pkg/radius -run '^$' -fuzz '^FuzzDecode$' -fuzztime=10s -parallel=2
```

Unit and fuzz coverage includes header and attribute truncation, all message
codes, exact minimum/maximum lengths, ignored padding, repeated/empty/opaque
attributes, invalid UTF-8, malformed vendor boundaries, circuit bounds, and
capture-buffer reuse. Fuzz invariants require no partial message on error and
exact reconstruction from all retained AVPs on success.

## Exact filters and complete groups

`CompilePredicate` accepts literal UTF-8 User-Name, a subscriber MAC with the
explicit `calling-station-id-uppercase-hyphen-v1` profile, or one complete hex
AVP. Supported AVPs are User-Name, NAS-Port-Id and vendor 3561/type 1
Agent-Circuit-Id. Matching revalidates the entire original message, uses exact
value bytes, and handles repeated attributes and grouped VSAs without rewriting
them. `Spec` serializes AVP targets as uppercase hex. NAI grammar validation
belongs to the future X1 adapter; the shared predicate retains target kind.

`CompileGroup` binds a complete conjunction to operator scope/profile revision
and optionally origin/source. It requires criterion IDs and positive revisions;
task ID and generation must appear together. `Group.Match` returns one complete
reference only when every criterion matches the same observation with valid
capture identity. Two groups never merge partial criteria. Ordinary references
have no task ID and cannot authorize LI. Scope fields describe the configured
boundary; callers still need to authenticate capture provenance.

## Bounded correlator

`NewCorrelator(CorrelatorConfig{})` uses the contract defaults: 30-second lifetime
and quiet guard, 65,536 candidates, four candidates per tuple, 64 MiB candidate
budget, 65,536 suppression keys and 96 MiB total charged state. Invalid limits
return an error. `Now` injects logical time; backward values are clamped. Replay
callers advance it using packet timestamps while retaining original capture time.

Call `Process` for every valid request and response before ordinary application
filter rejection. The result owns its storage. Identical request bytes reuse the
first instance without extending its lifetime or changing its evidence snapshot.
Distinct requests, including nonmatching ones and different code families,
prevent unique inheritance. Responses remain unbuffered. Every response has one
association outcome; direct evidence is independent of inheritance.

Expiry and capacity loss suppress the whole tuple. Traffic extends the quiet
guard; no surviving candidate becomes falsely unique. If guards cannot fit, the
correlator clears state and suppresses inheritance globally until a full quiet
period. Charged storage includes message/evidence copies, strings and conservative
map/backing-storage overhead. `Stats` exposes state occupancy and counters.
`Process` checks expiry synchronously and periodically sweeps; owners may also
call `Cleanup` while idle. `Close` releases state and permanently stops association;
there is no background goroutine to drain.

`EvidenceCurrent` must validate every member of a reference against one current
filter/task snapshot. With no callback, no references inherit, even when a unique
request is known. The callback runs under the correlator lock, receives owned
reference storage and must not reenter the correlator. Downstream task admission
must check generations again because filters can change after association.

## Management boundary

The additive management enum values 18–21 are `radius_username`, `radius_mac`,
`radius_attribute` and `radius_compound`. Structured criteria, complete ownership,
scope and revision survive protobuf and filter-file conversions. For example:

```bash
lc set filter -P localhost:55555 --insecure \
  --type radius_username --pattern 'alice@example.test' --revision 1
lc set filter -P localhost:55555 --insecure \
  --type radius_mac --pattern '02-00-00-00-00-01' --revision 1 \
  --radius-mac-profile calling-station-id-uppercase-hyphen-v1
lc set filter -P localhost:55555 --insecure \
  --type radius_attribute --pattern 57086C696E652D61 --revision 1 \
  --radius-operator-scope operator-a/nas-a --radius-profile-revision v1
```

Compound filters use `lc set filter --file`; every criterion's `filter_revision`
must equal the enclosing filter's `revision`. Increment all of them when modifying
criteria, scope or enablement. Task changes also require a new task generation.
The manager retains up to 65,536 revision records for its lifetime, including
deleted IDs, and rejects stale recreation or additional IDs at capacity. A
management restart must start fresh capture epochs and correlators before
accepting observations: deleted revision history is not persisted. `Manager.Load` is a startup-only
operation and rejects calls after successful restoration or an update.

A compound ordinary filter file can contain:

```yaml
filters:
  - id: radius-line-and-account
    type: radius_compound
    enabled: true
    revision: 1
    radius:
      group_id: line-and-account
      scope:
        operator_scope: operator-a/nas-a
        profile_revision: v1
      criteria:
        - filter_id: account
          filter_revision: 1
          kind: username
          value: alice@example.test
          target_kind: account
        - filter_id: line
          filter_revision: 1
          kind: attribute
          value: "57086C696E652D61"
          target_kind: line
```

Malformed RADIUS filter files fail restoration; misspelled RADIUS fields do not
silently disappear. The TUI displays RADIUS types and directs edits to the CLI so its simple
form cannot discard structured scope or revision data.

Distribution requires both the exact type string and `radius_filter_version=1`.
Explicit unsupported targets reject provisioning; broadcast distribution excludes
unsupported peers. Generic hunters with observation-aware forwarding advertise
version 1; local tap targets accept RADIUS filters only with both the capture
processor and observation matcher installed. `ApplicationFilter.MatchRADIUSObservation`
keeps grouped references separate from generic packet filter IDs.

### Ordinary capture and outputs

Generic hunt and tap decode and correlate before application selection, so an
unmatched competing request can prevent ambiguous response inheritance. Dedicated
RADIUS subcommands and operator-facing port/profile flags remain Phase 6 work.
The Go runtime configurations accept additional ports and capture scope; defaults
observe UDP 1812/1813 with ordinary `local`/`unconfigured` scope labels. Those
labels do not establish production operator isolation.

An active dynamic RADIUS filter expands the effective BPF with **both directions**
of the configured service ports. IPv6 UDP extension chains pass a broader
`ip6 protochain 17` predicate and receive port validation in userspace. This
expansion can admit traffic outside the base BPF: BPF selection is not an
operator/NAS authorization boundary. Scope-bound criteria and deployment isolation
remain required for scoped targets. Removing the filter restores ordinary BPF.

Capture restarts create fresh epochs. Queued pre-boundary timestamps cannot seed
or inherit a transaction across the gap. Correlation time follows monotonically
advancing validated capture timestamps, including accelerated offline replay.
Validation counters exclude unrelated traffic; noninitial UDP fragments have no
visible ports and are conservatively counted as fragmented candidates.

`lc process` validates and presents RADIUS without protocol mode or X1 tasks.
Legacy raw traffic receives processor-local observational association separated
by immediate source and interface; it has no capture-side authorization evidence.
Legacy reconnect continuity is not a trusted capture epoch. Distributed reconnect
and snapshot reconciliation acceptance remains Phase 7 work.

Generic sniff text/JSON, local and remote watch metadata, and the optional
`radius` TSV/JSONL stream use the public projection. Structured sniff logs and
CLI packets share observations when logs are enabled. Packet, upstream and
virtual-interface sinks preserve original bytes and link type independently;
RADIUS never selects VoIP per-call files. Malformed/unsupported RADIUS text uses
a rejection summary rather than gopacket's raw attribute dump.

### Capture provenance transport

`pipeline.PacketEnvelope.RADIUS` and additive `CapturedPacket.radius` version 1
retain capture origin/epoch, opaque observation and request identities, association
status, and complete generation-bearing criterion groups. Local capture adapters
clone observations; protobuf adapters own their byte slices. Upstream relays keep
the original scope instead of substituting their immediate transport identity.
Captured packet data, capture timestamp, lengths and link type remain authoritative.
The receiving adapter decodes attributes and endpoints again from those bytes and
checks the claimed RADIUS message, association shape, scope, and direct criteria.
Invalid claims are discarded while raw packet outputs remain available. Generic
SIP/RTP filter-ID fields are cleared whenever a RADIUS claim is received.

`ValidateProvenance` and `grpcadapter.RADIUSFromProto` establish consistency only.
A self-declared origin, filter ID, or unique association is not authenticated by
these checks. Inherited ownership cannot be proved from one response datagram.
LI admission must separately establish the trusted capture origin/relay path and
current task generations; this is Phase 4 work. Legacy packets without the
versioned envelope carry no inherited attribution, regardless of generic IDs.
The transport includes original message bytes and exact criteria for packet
processing; routine display and log consumers must use the redacted presentation
model rather than dumping the transport message.
