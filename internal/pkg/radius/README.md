# Shared RADIUS decoding

This package implements the Phase 1 validation and observation foundation for
the [RADIUS plan](../../../docs/plans/radius-poi-implementation.md). Matching,
transaction correlation, command wiring, distributed transport and X2 delivery
belong to later phases. Observational decoding does not authenticate RADIUS
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
owned by the future correlator; sinks and LI admission own their respective
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
Matching and association state are Phase 2 work: decoding cannot fabricate an
unmatched/ambiguous decision or inherited evidence. `Observation.Clone` deeply
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
