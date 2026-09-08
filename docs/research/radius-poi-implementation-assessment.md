# RADIUS POI implementation assessment

Date: 2026-09-08

## Objective

Implement a lippycat Point of Interception (POI) that observes a mirrored
BRAS-to-RADIUS link, matches subscriber identities against X1 targets, associates
responses with matched requests, and delivers the original RADIUS messages to an
MDF over X2 using payload format 11. RADIUS capture and analysis must also support
the ordinary lippycat output paths; X2 is one optional consumer, not the owner of
the capture pipeline.

This report assesses the existing code and proposes implementation boundaries.
It does not describe an implemented feature. The scope is exclusively lippycat.

## Findings

The existing capture and LI infrastructure can support this feature. The main
missing components are RADIUS-aware target matching, bounded transaction
correlation, authorization provenance for responses, and RADIUS X2 dispatch.
Adding an encoder or capture-port filter alone would not provide a working POI.

Two qualifications to the initial premise are important:

- Generic packet capture already collects RADIUS traffic. The existing gopacket
  dependency also contains a RADIUS decoder; lippycat lacks its own RADIUS
  analysis and matching integration.
- X1 schema membership does not mean operational support. `nai` is accepted but
  currently mapped to a SIP URI filter. `radiusAttribute` and `macAddress` are
  present in the schema but rejected by capability validation.

### Existing implementation

| Area                         | Evidence                                                                                                                       | Consequence                                                                                   |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| Generic capture              | [tap command](../../cmd/tap/tap.go), [shared runtime](../../cmd/tap/runtime.go)                                                | Reuse the capture engine and BPF configuration.                                               |
| Protocol integration         | [protocol catalog](../../internal/pkg/protocolcatalog/catalog.go)                                                              | RADIUS needs a protocol specification and integration if dedicated commands are provided.     |
| Decoder dependency           | `github.com/google/gopacket v1.1.19`, `layers/radius.go` and `layers/ports.go`                                                 | Reuse and audit `layers.RADIUS`; the default UDP mapping covers 1812, not 1813.               |
| X1 target schema             | [schema/x1.go](../../internal/pkg/li/x1/schema/x1.go)                                                                          | `Nai`, `RadiusAttribute`, and `MacAddress` are already represented in generated XML types.    |
| X1 validation                | [capabilities.go](../../internal/pkg/li/x1/capabilities.go), [capability tests](../../internal/pkg/li/x1/capabilities_test.go) | MAC and RADIUS attribute targets are currently rejected.                                      |
| Target mapping               | [filters.go](../../internal/pkg/li/filters.go), `mapTargetToFilterType`                                                        | NAI currently creates `FILTER_SIP_URI`, not a RADIUS identity filter.                         |
| Filter protocol              | [management.proto](../../api/proto/management.proto)                                                                           | No RADIUS-specific filter types exist.                                                        |
| Shared application filtering | [application_filter.go](../../internal/pkg/hunter/application_filter.go), `MatchPacketWithIDs`                                 | Shared integration point for hunt and tap matching.                                           |
| Raw transport                | [data.proto](../../api/proto/data.proto)                                                                                       | Raw packet transport and filter-ID carriage already exist.                                    |
| LI ingress                   | [processor_packet_pipeline.go](../../internal/pkg/processor/processor_packet_pipeline.go)                                      | Packets without matched filter IDs are skipped by packet LI processing.                       |
| X2 packet dispatch           | [processor_li.go](../../internal/pkg/processor/processor_li.go)                                                                | Existing packet X2 dispatch is SIP-specific.                                                  |
| X2 format                    | [pdu.go](../../internal/pkg/li/x2x3/pdu.go)                                                                                    | `PayloadFormatRADIUS = 11` already exists.                                                    |
| X2 encoder                   | [x2_encoder.go](../../internal/pkg/li/x2x3/x2_encoder.go)                                                                      | `EncodeIRI` requires VoIP metadata and a Call-ID.                                             |
| Delivery and lifecycle       | [LI manager](../../internal/pkg/li/manager.go), [delivery](../../internal/pkg/li/delivery/)                                    | Reuse task admission, generations, destination handling, sequencing, and queued TLS delivery. |

The optional [LI metadata sink](../../internal/pkg/li/metadata_sink.go) is not an
existing RADIUS delivery path. It accepts selected normalized protocol events
and emits a proprietary metadata payload. Raw format-11 delivery needs a
separate encoder and dispatch path.

## Proposed architecture

### Output contract

Captured RADIUS packets must enter the shared packet pipeline and be available
to all configured sinks supported by the running command/build:

| Output                     | Required integration                                                                                                                         |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| PCAP files                 | Preserve captured packets and link type through unified and non-VoIP rotating writers. Per-call VoIP writers are not the RADIUS output path. |
| Upstream processor         | Forward packets, RADIUS metadata, and attribution evidence through existing packet transport and adapters.                                   |
| TUI/monitoring subscribers | Broadcast packets with useful RADIUS protocol summaries and decoded metadata.                                                                |
| Virtual interface          | Inject captured packets using the existing interface/link-format handling.                                                                   |
| CLI text/JSON              | Expose decoded RADIUS observations through the sniff command's output conventions.                                                           |
| Structured protocol logs   | Map RADIUS observations into typed events and a documented TSV/JSONL schema using the existing event/log pipeline.                           |
| X2                         | Apply current task authorization and encode the original RADIUS message using payload format 11.                                             |

PCAP, upstream forwarding, TUI subscription, and virtual-interface injection
already exist in the processor pipeline. RADIUS-specific CLI output, display
metadata, typed events, and structured-log schemas require integration work.
Structured logs describe observations; they are not a byte-preserving packet
sink. Follow the canonical schema machinery rather than defining fields inside
individual writers.

Ordinary capture, matching, and outputs must work without an LI build or an X1
task. Provide ordinary RADIUS filters as well as X1-derived filters. Keep ordinary
capture selection separate from LI delivery authorization: a packet being
captured or displayed does not authorize X2, and an X2 admission failure must
not suppress independently configured ordinary outputs.

Sink enablement is independent within each command's supported capabilities.
Use existing queue/backpressure policies and counters; a slow TUI subscriber must
not block capture or become a reason for hunter flow control. Preserve captured
bytes for packet sinks, and perform RADIUS-only payload extraction at the X2
encoder boundary.

```text
Mirrored BRAS ↔ RADIUS traffic
              │
              ▼
Generic capture + RADIUS port/BPF configuration
              │
              ▼
RADIUS validation and attribute extraction
              │
              ▼
Exact target matcher + bounded request/response correlator
              │
              ├── tap: local packet source
              └── hunt: existing packet transport → processor
                                      │
                                      ▼
                           Shared packet pipeline
                             │                 │
                             ▼                 ▼
                PCAP / upstream / TUI /    LI provenance and
                   virtual interface      task admission
                                               │
                                               ▼
                                      RADIUS X2 → MDF

Decoded observations → CLI output / typed events → structured logs
```

The matcher and correlator should be shared by hunt and tap. Tap combines local
capture and processor capabilities, so separate implementations would risk
different attribution and delivery behavior.

### Component boundaries and observation contract

Keep decoding, target matching, transaction correlation, and X2 encoding as
separate components. The encoder should consume an attributed RADIUS observation
rather than own the request table or perform target matching itself.

Expose a reusable observation containing:

- The original validated RADIUS bytes and all decoded attributes, preserving
  unknown attributes, repeated values, and their ordering.
- Capture timestamp, source node/interface or equivalent capture scope, network
  endpoints, and NAS identity attributes when present. Keep observed transport
  endpoints distinct from NAS identity; a RADIUS proxy can make them different.
- Request/response association with an opaque transaction identity and explicit
  association status, including missing or ambiguous requests.
- Matched target/filter references, authorizing task generation, and whether
  attribution is direct or inherited from a request.

Use immutable observations or explicit byte ownership so asynchronous consumers
cannot read reused capture buffers. Additional consumers must not block packet
capture or X2 delivery; any asynchronous dispatch must have bounded queues,
defined overflow behavior, and counters.

Treat the eight-bit RADIUS Identifier solely as one component of transaction
matching. Do not present it as a subscriber-session identity. Decode address and
accounting attributes faithfully without interpreting their presence as proof
of current address ownership. The X2 POI does not require an address-ownership
registry or dynamic subscriber IP filters.

## Required implementation

### 1. Decode and preserve RADIUS messages

Introduce a shared RADIUS package, for example `internal/pkg/radius`, wrapping
the existing decoder. Extract Code, Identifier, Length, Authenticator, and
attributes while preserving the original RADIUS bytes for delivery.

Explicitly decode authentication, accounting, and configured ports rather than
depending solely on gopacket's default port registration. Validate packet and
attribute lengths, handle truncation, preserve repeated and unknown attributes,
and define how fragmented IP packets are handled. Audit and fuzz the dependency
wrapper before treating it as a robust input boundary.

The first scope should cover visible UDP Access-Request,
Access-Accept/Reject/Challenge, Accounting-Request, and Accounting-Response
traffic. CoA/Disconnect and other transports should have explicit scope decisions.
Encrypted capture requires a separate plaintext/decryption integration and is
not supplied by this proposal.

### 2. Define target semantics and extend X1 support

Provide exact matching for `User-Name`, with an explicit policy for case, realm,
and byte handling. Do not inherit SIP substring or normalization behavior merely
because NAI values resemble SIP identities.

For MAC targets, match the subscriber identity carried in RADIUS attributes.
The Ethernet source on the mirrored link identifies infrastructure and is not
evidence of the subscriber's MAC. `Calling-Station-Id` is a possible source,
subject to the BRAS configuration and access technology. RFC 3580 specifies MAC
encoding for IEEE 802.1X; that convention must not be assumed for every BRAS.

Support requires coordinated changes to:

- Internal target types and their string representations.
- X1 activation/modification validation and target conversion in both directions.
- ADMF reconciliation, persisted task restoration, and registry validation.
- Filter types, serialization, distribution, and capability reporting.
- Exact MAC normalization and supported RADIUS attribute representations.

The initial release must support a defined subset of X1 `radiusAttribute`, not
defer attribute targeting as a whole. TS 103 221-1 V1.23.1, table 6.2.1.2-2,
defines the RADIUS target format as a subscriber-identifying RADIUS AVP encoded
as binary octets. The XML member is hex-encoded binary. Support User-Name
(type 1), NAS-Port-Id (type 87), and DSL Forum Agent-Circuit-Id (Vendor-Specific
type 26, vendor ID 3561, vendor type 1). Additional vendor forms remain unsupported
until their structure and semantics are explicitly implemented.

NAI and SIP URI are distinct identity types. The existing `nai` to
`FILTER_SIP_URI` mapping is a semantic bug, not behavior to preserve. Correct it
to a dedicated RADIUS User-Name path for this scope; SIP URI targets continue to
use SIP filtering. Remove obsolete SIP filters and invalidate their authorization
when migrating active or persisted NAI tasks, including restoration and ADMF
reconciliation. Do not silently convert those tasks into SIP URI targets.
RADIUS processing must remain independent of VoIP.

### Administrative identities and concrete X1 targets

German TR TKÜV 8.4, Part B, Annex A.1, section 3.2.2.2, page 100, defines
`lineID` as the line identifier or technical key of an internet access connection
and `userName` as its account name. These national administrative identifiers
need not have identically named X1 elements. The operator's administration system
can translate them into concrete interception criteria.

The following is the proposed deployment mapping, not a standardized
NatParas-to-X1 conversion:

| Administrative identity                     | X1 target for this POI                                                                             |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Account name conforming to the NAI contract | `nai`, matched against RADIUS User-Name                                                            |
| Other RADIUS account name                   | `radiusAttribute` containing a complete User-Name AVP                                              |
| Line identifier present in NAS-Port-Id      | `radiusAttribute` containing a complete NAS-Port-Id AVP                                            |
| Line identifier present in Agent-Circuit-Id | `radiusAttribute` containing a complete Vendor-Specific AVP for vendor 3561/type 1                 |
| Inventory-only line identifier              | Resolve upstream to the concrete attribute value and required network scope before provisioning X1 |

NAI is an identity format commonly carried in User-Name, not a synonym for every
account name. Preserve target type and original value even when `nai` and a
User-Name AVP share an exact matcher; do not add or strip realms implicitly.
X1 also offers ServiceAccessIdentifier, but it does not specify a RADIUS attribute
mapping. It is not required for the initial subset.

NAS-Port-Id identifies a NAS connection port; Agent-Circuit-Id describes the
subscriber's logical access-loop port. Neither is automatically identical to a
particular operator's administrative lineID. Confirm the mapping using operator
documentation and a known-line capture. Values may require NAS/access-node and
operator scope to be unique. Keep inventory lookup outside the initial lippycat
implementation: accept explicitly provisioned concrete values and reject
unresolved or insufficiently scoped criteria rather than guessing.

### Attribute matching contract

Parse each target as one complete AVP, validating type, total length, and value.
For the initial VSA target representation, require exactly one supported
sub-attribute with valid outer length, vendor ID, vendor type, and inner length.
Match its decoded vendor/type/value against sub-attributes in captured VSAs,
including VSAs that group multiple sub-attributes. Do not require identical VSA
container packing and do not search arbitrary payload bytes. Preserve original
packet bytes separately for X2.

Use exact value-byte matching for this subset, with no substring matching or
implicit case/realm transformations. Repeated packet attributes match when an
instance satisfies the predicate, after complete message validation. Multiple
criteria within one X1 task must all match, as required by TS 103 221-1; separate
tasks retain independent attribution. Implement or explicitly reject unsupported
criterion combinations, never flatten them into an OR of filter IDs. Carry
required network scope through filter distribution and authorization evidence;
do not confuse NAS identity attributes with observed proxy transport endpoints.
Document whether scope is enforced by a dedicated POI deployment or supported
conjunctive criteria. Unsupported attributes, malformed hex/AVPs, and ambiguous
scope must fail activation/modification rather than broaden selection.

Initially validate RADIUS tasks as X2-only. Raw RADIUS delivery does not implement
subscriber content interception or an X3 service.

### 3. Associate responses with requests

The RADIUS Identifier is only eight bits and is not globally unique. The
correlator should use capture scope, client/server address and port tuple, and
Identifier, retaining request Code, Authenticator, matched targets, and the
authorizing task/filter generation.

Responses copy the request Identifier. Their Authenticator is not a copy of the
request Authenticator; cryptographic verification requires the shared secret.
Retaining the request Authenticator helps distinguish request instances and
retransmissions, but does not by itself prove response ownership.

Define behavior for Identifier reuse, retransmissions, reordered packets,
duplicate mirror observations, and multiple outstanding candidates. Ambiguous
responses must not inherit a target match. Bound memory with capacity limits and
expiry, and expose expiration, collision, ambiguity, and capacity-drop counters.

Request/response association is distinct from subscriber-session tracking.
Relating separate authentication and accounting exchanges, or accounting
messages that omit the target identity, requires additional state and scoped
session keys such as NAS identity plus `Acct-Session-Id`. It is not solved by
retaining an Identifier indefinitely.

### 4. Integrate before packet rejection

Both [hunter forwarding](../../internal/pkg/hunter/forwarding/manager.go) and
the [tap local source](../../internal/pkg/processor/source/local.go) consume the
shared application filter. Response association must run before an identity-free
response is rejected as unmatched.

The preferred distributed implementation matches at capture ingress and carries
the resulting evidence to the processor. A processor-side alternative requires
forwarding all relevant RADIUS packets and running matching before the existing
LI filter-ID gate. BPF capture alone does not bypass that gate.

Raw transport can be reused. Dedicated RADIUS metadata and correlation evidence
may require protobuf and normalized packet-envelope extensions. If metadata is
added, update both distributed adapters and the local tap path. RADIUS TUI
summaries, CLI output, typed events, and structured logs are part of the protocol
integration scope, alongside format-11 delivery.

### 5. Validate authorization provenance

Keep a direct attribute match distinct from a response match inherited through
a transaction. Existing `validatedFilterIDs` logic in the LI manager has special
validation for RTP; non-RTP packets currently take the direct/inherited union.
RADIUS needs its own transaction provenance validation.

Invalidate or reject stale associations after task modification, deactivation,
expiry, and reactivation. A reused filter identifier must not authorize a
response from a previous task generation. Preserve multi-target/task attribution
without merging ambiguous transaction owners.

Reuse `AcquireTaskAdmission`, activation generations, and delivery metadata so
authorization is checked at delivery admission as well as initial matching.
Use the existing destination lifecycle and queued-delivery safeguards.

### 6. Encode and deliver X2

Add a RADIUS encoder and processor dispatch branch. ETSI TS 103 221-2 table
5.4.1-1 assigns format 11 to RADIUS on X2. Clause 5.4.12 requires the RADIUS
packet without IP/UDP encapsulation. Deliver the original RADIUS header,
Authenticator, and attributes, bounded by the validated RADIUS Length; do not
deliver the full captured Ethernet frame or reconstruct the message from a
normalized attribute map.

Reuse the PDU builder, common attributes, shared sequencer, timestamps, endpoint
metadata, and queued X2 delivery. Define X2 Correlation ID semantics separately
from the RADIUS Identifier, including any required MDF session convention.
Request/response direction on the AAA link does not automatically establish
direction relative to the subscriber; leave Payload Direction unknown unless
the selected service semantics justify it.

### 7. Expose configuration and operations

Use `radius` as the protocol object, consistent with existing `dns`, `tls`,
`http`, `email`, and `voip` commands:

| Proposed command  | Responsibility                                                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lc sniff radius` | Local RADIUS capture, decoding, filtering, CLI output, and supported local file/log outputs.                                                            |
| `lc hunt radius`  | Edge capture and RADIUS matching, including response association, followed by forwarding to a processor.                                                |
| `lc tap radius`   | Standalone capture and processing with configured PCAP, upstream forwarding, TUI serving, virtual interface, structured logs, and optional X2 delivery. |

These are proposed commands, not currently available functionality. Implement
them as thin protocol specifications over one shared decoder, matcher, and
transaction tracker. Ordinary operation must not require LI; X1 and X2 remain
optional capabilities of LI-enabled processing.

Keep `lc process` protocol-neutral: it accepts RADIUS alongside other traffic.
Existing `lc watch` commands should display RADIUS through the shared metadata
and rendering path, without requiring a `watch radius` command.

RADIUS is the actual AAA protocol on the mirrored link in this deployment.
BRAS (Broadband Remote Access Server) and BNG (Broadband Network Gateway) name
network roles/equipment, not a packet protocol. Naming the command `bras` or
`bng` would imply a broader device/service scope and would unnecessarily tie
general RADIUS capture to broadband access. Protocol behavior and configured
attributes determine matching; device terminology belongs in deployment
examples and capture-scope configuration.

Provide configuration for capture ports, MAC attribute interpretation,
ordinary exact attribute filters, operator/access-line mapping profiles and
scope, transaction expiry and capacity, and protocol scope. Mapping profiles
describe concrete attribute selection; they do not perform inventory resolution.
Retain non-LI builds through the existing build-tag/stub architecture.

Expose counters for malformed packets, matched requests, correlated responses,
unmatched/ambiguous responses, stale-generation rejection, state exhaustion,
and X2 encoding/delivery outcomes. Follow existing counter ownership conventions
to avoid counting the same rejection at multiple pipeline stages.

## Verification requirements

The following are proposed acceptance checks, not completed work:

- [ ] PCAP fixtures demonstrate Access-Accept, Reject, Challenge, and accounting response delivery.
- [ ] User-Name and MAC matching is exact and follows documented normalization rules.
- [ ] X1 User-Name, NAS-Port-Id, and vendor 3561/type 1 Agent-Circuit-Id AVPs activate, modify, round-trip, restore, and distribute correctly; unsupported forms are rejected.
- [ ] Line targeting matches known-line fixtures in the correct operator/NAS scope, including VSA packing variations; unresolved values and cross-scope collisions cannot authorize delivery.
- [ ] Malformed target hex/outer/inner lengths, repeated attributes, and conjunctive multi-criterion tasks have deterministic fail-closed behavior.
- [ ] NAI-to-SIP migration removes obsolete filters and stale authorization while explicit SIP URI targets retain their behavior.
- [ ] Repeated, unknown, malformed, and truncated attributes are handled without panic or false attribution.
- [ ] Simultaneous clients and capture scopes can reuse Identifiers without cross-target delivery.
- [ ] Retransmission, Identifier reuse within a tuple, duplicates, and reordered packets have deterministic behavior.
- [ ] Identity-free responses inherit only a uniquely established, current authorization.
- [ ] Missing requests and ambiguous candidates do not cause inherited target delivery.
- [ ] Expiry and capacity limits bound memory and expose losses.
- [ ] Task modification, deactivation, expiry, and reactivation invalidate stale associations and queued authorization.
- [ ] Golden X2 fixtures preserve original RADIUS bytes and verify format, sequence, correlation, and attributes.
- [ ] Tap and hunt/process produce equivalent attribution and X2 output for equivalent input.
- [ ] PCAP, upstream forwarding, TUI, and virtual-interface outputs receive RADIUS packets through the ordinary pipeline, independently of X2 enablement.
- [ ] Ordinary RADIUS filters and outputs work without LI or an X1 task; LI delivery still requires its own authorization.
- [ ] CLI output and canonical structured-log schemas expose decoded RADIUS observations consistently.
- [ ] Multiple enabled sinks preserve packet bytes and metadata and follow existing bounded queue and subscriber isolation policies.
- [ ] Appropriate LI and non-LI build checks pass; concurrency-sensitive correlation and lifecycle tests pass under the race detector.

## Recommended delivery scope

Start with a tap-based POI for visible UDP authentication and accounting traffic,
exact User-Name/MAC matching, the required User-Name/NAS-Port-Id/Agent-Circuit-Id
X1 AVP subset, bounded request/response association, and X2-only delivery.
Build the matcher and correlator as shared components and verify
hunt/process parity before describing distributed RADIUS POI support as complete.

Implement the NAI mapping correction with migration safeguards. Finalize operator
MAC/line attribute mappings, scope enforcement, the AVP contract above, and MDF
correlation expectations before dependent implementation. These choices affect
correctness more than the encoder itself. Arbitrary AVPs and automatic inventory
resolution remain outside the initial scope; the defined AVP subset is required.

Cross-exchange subscriber-session tracking, CoA/Disconnect, and encrypted
transports can be scoped separately. This POI
does not by itself provide subscriber user-plane capture or raw-IP IRI/CC session
correlation.

## Sources and review limits

- Code references above were inspected in the working tree on 2026-09-08.
- [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865.html): RADIUS packet structure, attributes, Identifier, and request/response authentication.
- [RFC 3580, section 3.21](https://www.rfc-editor.org/rfc/rfc3580.html#section-3.21): Calling-Station-Id MAC convention for IEEE 802.1X.
- [RFC 7542](https://www.rfc-editor.org/rfc/rfc7542.html): NAI syntax and carriage in RADIUS User-Name.
- [RFC 2869, section 5.17](https://www.rfc-editor.org/rfc/rfc2869.html#section-5.17): NAS-Port-Id semantics and encoding.
- [RFC 4679, section 3.3.1](https://www.rfc-editor.org/rfc/rfc4679.html#section-3.3.1): DSL Forum VSA encoding and Agent-Circuit-Id.
- [ETSI TS 103 221-1 V1.23.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.23.01_60/ts_10322101v012301p.pdf): Table 6.2.1.2-2 RADIUS/NAI target formats and conjunctive task criteria in table 6.2.1.2-1.
- [ETSI TS 103 280 V2.18.1, section 6.58](https://www.etsi.org/deliver/etsi_ts/103200_103299/103280/02.18.01_60/ts_103280v021801p.pdf): ServiceAccessIdentifier semantics.
- [TR TKÜV 8.4](https://www.bundesnetzagentur.de/SharedDocs/Downloads/DE/Sachgebiete/Telekommunikation/Unternehmen_Institutionen/Anbieterpflichten/OeffentlicheSicherheit/TechnUmsetzung110/Downloads/TR_TKUEV_Ausgabe_8.4.pdf?__blob=publicationFile&v=1): Part B, Annex A.1, sections 3.2.2.2 and 3.2.2.5, national lineID/userName definitions and locating criteria.
- [Juniper subscriber management overview](https://www.juniper.net/documentation/us/en/software/junos/subscriber-mgmt-getting-started/topics/topic-map/subscriber-management-introduction.html): BNG subscriber management and use of RADIUS for AAA.
- [ETSI TS 103 221-2 V1.10.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.10.01_60/ts_10322102v011001p.pdf): X2 payload format 11 and RADIUS encapsulation requirements.

This assessment is based on source inspection and the cited protocol documents.
No implementation, live capture, MDF interoperability test, or test-suite run
was performed. BRAS attribute conventions and the receiving MDF's service
contract remain deployment-specific inputs.
