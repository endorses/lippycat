# RADIUS POI implementation plan

Date: 2026-09-08

Status: Planned; no implementation or acceptance checks completed.

Source: [RADIUS POI implementation assessment](../research/radius-poi-implementation-assessment.md).

## Objective and scope

Add ordinary RADIUS capture, filtering, analysis, and outputs, with optional
X1-authorized delivery of original RADIUS messages over X2 using payload format 11. Start with a tap-based POI observing visible UDP authentication and accounting
traffic. Complete hunt/process parity before claiming distributed POI support.

The initial protocol scope covers Access-Request, Access-Accept, Access-Reject,
Access-Challenge, Accounting-Request, and Accounting-Response on UDP ports 1812,
1813, and explicitly configured ports. Exact User-Name and configured subscriber
MAC matching are required. Initial X1 `radiusAttribute` support must cover
User-Name (type 1), NAS-Port-Id (type 87), and DSL Forum Agent-Circuit-Id
(type 26 Vendor-Specific, vendor ID 3561, vendor type 1). Arbitrary attributes
and other vendor formats remain outside this defined subset.

Cross-exchange subscriber-session tracking, dynamic subscriber IP filters,
user-plane interception, X3, CoA/Disconnect, and encrypted transports are outside
this release. An accounting exchange without a matching identity does not become
authorized merely because an earlier authentication exchange matched.

Automatic operator inventory lookup is also outside this release. Administrative
lineID values that are absent from RADIUS must be resolved upstream into concrete
attribute values and sufficient network scope before X1 provisioning.

## Architecture and invariants

Use a shared `internal/pkg/radius` implementation for decoding, exact matching,
and bounded transaction correlation. Run response association before application
filter rejection in hunt and tap. Carry observations and attribution evidence
through the existing local and distributed packet adapters. Keep X2 encoding and
task authorization in the LI layer.

RADIUS commands and protocol processing are independent of VoIP. NAI and SIP
URI are distinct target types: the existing X1 `nai` to `FILTER_SIP_URI` mapping
is a semantic bug to correct, not compatibility behavior to preserve. SIP URI
targets belong to SIP filtering; RADIUS NAI targets match User-Name through a
dedicated RADIUS filter. Shared capture, transport, and LI infrastructure does
not imply shared identity semantics or a dependency on VoIP metadata.

Ordinary capture selection and LI authorization remain separate. PCAP, upstream,
TUI, virtual-interface, CLI, and structured-log outputs operate independently of
X2 within each command's existing capabilities. An LI admission rejection must
not suppress independently selected ordinary output.

Packet sinks retain captured bytes and link type. X2 alone extracts the validated
RADIUS message, excluding network encapsulation and trailing padding. Structured
logs describe observations and are not byte-preserving packet output.

The eight-bit Identifier is a transaction matching input, never a subscriber
session identity. Transport endpoints remain distinct from NAS attributes.
Ambiguous response ownership cannot confer inherited authorization. Capture-side
filter evidence is subject to current processor-side task admission.

## Administrative-to-X1 mapping

Use the following deployment mapping, as explained and sourced in the research
document. It is not a standardized NatParas-to-X1 conversion.

| Administrative identity                   | X1 representation and matching                                                     |
| ----------------------------------------- | ---------------------------------------------------------------------------------- |
| `userName` conforming to the NAI contract | `nai` matched against User-Name                                                    |
| Other RADIUS `userName`                   | `radiusAttribute` with a complete User-Name AVP                                    |
| `lineID` carried in NAS-Port-Id           | `radiusAttribute` with a complete NAS-Port-Id AVP                                  |
| `lineID` carried in Agent-Circuit-Id      | `radiusAttribute` with a complete vendor 3561/type 1 VSA                           |
| Inventory-only `lineID`                   | Upstream resolution into one of the supported concrete criteria and required scope |

Keep NAI, account names, and line identifiers distinct even where matchers are
shared. Do not implicitly add/strip realms or assume a NAS port uniquely
identifies a subscriber across the operator's network. ServiceAccessIdentifier
is an available X1 alternative for an agreed service identity contract, but is
not needed for this initial RADIUS subset.

## Phase 0 — Resolve contracts and acceptance fixtures

The NAI mapping correction and migration policy are settled: X1 `nai` maps to
the dedicated RADIUS User-Name filter, and SIP URI filtering requires the SIP
URI target type. Migrating active or persisted NAI tasks removes obsolete SIP
filters and invalidates their authorization evidence; it never converts NAI
targets into SIP URI targets. Phase 4 implements and verifies this decision.

Dependent matching and LI work must wait for the remaining relevant decisions
below.
Decoder and ordinary output work can proceed once the observation contract is
settled. Record decisions in this plan or a linked design document.

- [ ] Specify exact User-Name semantics: default to byte-exact, case-sensitive matching with no realm stripping, Unicode normalization, or SIP substring behavior; define how textual X1 values map to bytes and how invalid encodings are rejected or represented.
- [ ] Select the subscriber MAC attribute and accepted encodings for the deployment. Make Calling-Station-Id interpretation explicit, reject malformed or decorated values outside the selected convention, and never use mirrored Ethernet addresses as subscriber identity.
- [ ] Finalize the required `radiusAttribute` contract: one complete hex-encoded AVP; User-Name, NAS-Port-Id, or a vendor 3561/type 1 VSA containing exactly one target sub-attribute. Validate outer/inner lengths and use exact value-byte matching; reject unsupported types, vendors, malformed encodings, and extra target sub-attributes.
- [ ] Establish operator line-attribute mappings with documentation and known-line fixtures. Define necessary operator/NAS/access-node scope and how it is enforced through dedicated POI deployment or supported conjunctive X1 criteria. Accept explicitly provisioned resolved values; keep inventory lookup upstream and reject unresolved or insufficiently scoped targets.
- [ ] Define repeated-attribute matching as an exact matching instance in a fully validated packet; match a VSA target by vendor/type/value regardless of captured sub-attribute grouping. Preserve AND semantics for all criteria within one X1 task and independent ownership across tasks; reject unsupported combinations.
- [ ] Agree with the receiving MDF on X2 Correlation ID scope, lifetime, request/response reuse, and encoding. Do not equate it with the RADIUS Identifier. Keep Payload Direction unknown unless the service contract supports a stronger value.
- [ ] Define fragment handling for IPv4 and IPv6. For the initial release, prefer rejecting fragmented datagrams from RADIUS analysis and LI attribution with a counter, while retaining them in independently configured generic packet outputs; require bounded reassembly if fragments must be supported.
- [ ] Define timeout and capacity defaults, capture-scope identity across reconnects/restarts, retransmission retention, duplicate delivery policy, and behavior for responses observed before requests. Default to no retroactive inherited authorization without a separately bounded design.
- [ ] Record that association without a RADIUS shared secret is observational, not cryptographic authentication; define fail-closed behavior for multiple plausible request instances.
- [ ] Create synthetic, non-sensitive PCAP fixtures and expected observations for all six supported message codes, both IP families, accounting/custom ports, multiple clients, and multiple capture scopes. Include expected raw RADIUS payloads for X2 golden checks.

Exit criterion: target mapping, identity semantics, association policy, and MDF
expectations are explicit; unsupported scope is documented rather than accepted
implicitly.

## Phase 1 — Shared decoder and observation model

Primary locations: new `internal/pkg/radius`, `internal/pkg/types`,
`internal/pkg/protocolmeta`, and `internal/pkg/protocolcatalog`.

- [ ] Audit the pinned gopacket RADIUS decoder and wrap it with explicit UDP payload decoding for authentication, accounting, and configured ports; do not depend on the default 1812 registration.
- [ ] Validate header, declared message length, attribute boundaries, packet truncation, and supported message codes. Preserve the exact validated header, Authenticator, and attribute bytes, including unknown and repeated attributes in wire order.
- [ ] Define an observation carrying capture time/scope, endpoints, separate NAS identity fields, original message bytes, decoded attributes, opaque transaction identity, association status, and direct/inherited attribution references with generation information.
- [ ] Specify ownership and copying at asynchronous boundaries so capture-buffer reuse cannot change observations or packet payloads; avoid making non-LI packages depend on LI implementation types.
- [ ] Implement explicit outcomes for malformed, unsupported, fragmented, unmatched, and ambiguous observations, with one counter owner per outcome.
- [ ] Add unit tests and bounded fuzz runs for decoder length handling, unknown/repeated attributes, malformed vendor attributes, truncation, and arbitrary input; verify no panic or false identity extraction.

Exit criterion: valid packets produce stable byte-preserving observations and
invalid input cannot enter target attribution.

## Phase 2 — Exact filters and bounded transaction association

Primary locations: `internal/pkg/radius`, `internal/pkg/filtering`,
`internal/pkg/hunter/application_filter.go`, `api/proto/management.proto`,
and filter management/capability adapters.

- [ ] Add ordinary RADIUS User-Name, subscriber MAC, and required-subset attribute filters with exact matchers, validation, serialization, and CLI management support. Reuse the AVP predicate implementation for ordinary and X1-derived filters while keeping authorization separate.
- [ ] Implement structured AVP/VSA predicates and compound task criteria with scope binding. Preserve target kind, criterion grouping, and operator/NAS scope through filter distribution; never authorize a conjunctive task from one independently matched filter ID.
- [ ] Extend protobuf enums additively without reusing field or enum numbers, regenerate bindings using repository tooling, and update distribution, supported-filter reporting, persistence, and display conversions.
- [ ] Define behavior for older hunters/processors: unsupported RADIUS filters or missing required provenance must not silently degrade to broader LI matching. Test capability rejection and ordinary raw-packet compatibility.
- [ ] Implement a concurrent bounded correlator keyed by capture scope, client/server IP and UDP ports, and Identifier, retaining request code, Authenticator, request-instance identity, matches, and filter/task generations.
- [ ] Enforce compatible request/response code families. Distinguish retransmissions from distinct request instances, including same-Identifier reuse, and avoid overwriting competing candidates into a false unique match.
- [ ] Define safe candidate retention after ambiguity, expiration, and capacity pressure so losing state cannot make a known competing request appear uniquely authorized; use bounded suppression/tombstone state or an equivalent conservative policy.
- [ ] Keep direct attribute matches separate from inherited matches. Inherit only from a unique eligible request; preserve multiple target/task references on that request without combining competing owners.
- [ ] Implement expiry, hard memory/candidate limits, cleanup/shutdown, and counters for collisions, ambiguity, expiration, and capacity loss. Ensure nonmatching competing requests participate in ambiguity detection.
- [ ] Test simultaneous tuples/scopes, Identifier wrap/reuse, retransmissions, duplicate mirrors, reversed/reordered traffic, absent requests, incompatible codes, eviction, and concurrent filter changes with an injectable clock.
- [ ] Test exact User-Name/NAS-Port-Id/Agent-Circuit-Id matches, malformed target hex and nested lengths, unsupported types/vendors, repeated attributes, VSA grouping variations, partial compound matches, and identical line values under different NAS/operator scopes.

Exit criterion: deterministic association is bounded in memory and never grants
inherited attribution from missing, ambiguous, or stale evidence.

## Phase 3 — Capture ingress, transport, and ordinary outputs

Primary locations: `internal/pkg/hunter/forwarding/manager.go`,
`internal/pkg/processor/source/local.go`, `internal/pkg/pipeline/captureadapter`,
`internal/pkg/pipeline/grpcadapter`, `api/proto/data.proto`,
`internal/pkg/processor`, `internal/pkg/events`, `internal/pkg/logschema`,
`internal/pkg/logstream`, and the sniff/TUI presentation paths.

- [ ] Invoke the shared decoder/matcher/correlator before the hunt forwarding and tap local-source unmatched-packet gates. Include both directions in BPF generation and preserve visibility of competing requests needed for safe correlation.
- [ ] Extend the normalized packet envelope and protobuf metadata with RADIUS observations and provenance as needed; preserve capture scope, timestamp, link type, bytes, and attribution through local, gRPC, and upstream forwarding adapters.
- [ ] Define trusted provenance boundaries and validate envelope consistency against captured bytes. Do not treat a transported filter ID alone as proof of a RADIUS transaction association.
- [ ] Keep RADIUS handling protocol-neutral at `lc process`; integrate analyzer selection and protocol detection without requiring a separate processor command or an X1 task.
- [ ] Add shared RADIUS display metadata, protocol summaries, and existing watch/TUI rendering support; expose decoded observations through sniff text/JSON conventions.
- [ ] Add typed RADIUS observation events and a canonical `radius` log schema with versioned fields/types, transaction/association status, and documented attribute representation. Integrate TSV/JSONL encoding, rotation, configuration, and schema golden fixtures.
- [ ] Document and test which attributes are exposed in text/log outputs, particularly credential-bearing and binary values; retain byte preservation for explicitly configured packet/X2 sinks without blindly dumping every raw attribute into routine summaries.
- [ ] Verify unified/rotating PCAP, upstream forwarding, subscriber broadcast, and virtual-interface injection retain their existing behavior. Do not route RADIUS through per-call VoIP writers.
- [ ] Verify independent sink enablement, bounded queues, overflow counters, graceful draining, and subscriber isolation; slow TUI clients must not drive hunter flow control.

Exit criterion: non-LI capture and filtering work with useful metadata and all
supported ordinary outputs, including identity-free correlated responses.

## Phase 4 — X1 targets and current-generation authorization

Primary locations: `internal/pkg/li` target types, filters, registry, manager,
restoration/reconciliation paths, and `internal/pkg/li/x1` capabilities and
target conversions. Read the LI package instructions before implementation.

- [ ] Correct X1 `nai` mapping to the dedicated RADIUS User-Name filter and implement exact MAC target mapping. Keep SIP URI targets mapped to SIP filters, with no NAI-to-SIP fallback or VoIP dependency; keep unsupported attribute forms rejected.
- [ ] Update target string representations, bidirectional X1 conversion, activation/modification validation, capability reporting, ADMF reconciliation, persisted restoration, and registry validation together.
- [ ] Support the required AVP subset through all X1 lifecycle and round-trip paths, including hex-binary serialization and subset-aware capability/validation behavior. Preserve conjunctive criteria and current-generation scope evidence for direct requests and inherited responses; reject unsupported AVPs/combinations explicitly.
- [ ] Apply the migration policy to existing NAI tasks and their distributed filters, including reconnect/restoration paths. Test that obsolete SIP filters and queued authorization cannot survive correction and that explicit SIP URI targets continue to work.
- [ ] Document the corrected NAI mapping and migration behavior for operators, including the requirement to use explicit SIP URI targets for SIP filtering.
- [ ] Reject RADIUS task requests for X3 or combined delivery; accept only the supported X2 service/profile and valid destination configuration.
- [ ] Extend distributed filter evidence with the generation binding required for RADIUS. Define how capture-side filter revisions map to authoritative task generations, including updates racing packet transport.
- [ ] Add RADIUS-specific provenance validation before the current non-RTP direct/inherited union can authorize delivery; verify direct matches and inherited transaction evidence separately.
- [ ] Reuse `AcquireTaskAdmission`, activation generations, delivery metadata, and destination lifecycle safeguards. Reject stale evidence after modify, deactivate, expire, restore, and reactivate events, even when filter IDs are reused.
- [ ] Test multiple tasks matching one valid request, removal of one owner, stale queued packets, destination changes, and generation changes between initial matching and delivery admission; ordinary outputs must remain unaffected by rejection.

Exit criterion: only current authorized tasks can admit RADIUS X2 delivery;
stale or ambiguous inherited references cannot bypass validation.

## Phase 5 — Raw RADIUS X2 encoding and tap POI

Primary locations: `internal/pkg/li/x2x3`,
`internal/pkg/processor/processor_li.go`, and the LI packet ingress path.

- [ ] Add a RADIUS encoder consuming an attributed observation without requiring VoIP metadata or Call-ID and without owning matching/correlation state.
- [ ] Use `PayloadFormatRADIUS = 11` and the original bytes bounded by validated RADIUS Length; exclude Ethernet/IP/UDP and padding, and never reconstruct payload from decoded attributes.
- [ ] Reuse common PDU attributes, shared sequencing, capture timestamps, endpoint metadata, approved Correlation ID semantics, and queued TLS X2 delivery; keep subscriber-relative direction unknown unless justified.
- [ ] Dispatch RADIUS separately from SIP packet IRI and proprietary normalized metadata delivery. Verify ingress reaches RADIUS provenance validation before generic LI filter-ID handling can discard or admit it incorrectly.
- [ ] Add golden PDU tests for all supported exchanges, repeated/unknown attributes, non-VoIP observations, byte identity, format, sequencing, correlation, direction, timestamps, and endpoint attributes.
- [ ] Run tap fixture integration against a local test MDF receiver; test delivery pressure, encoder failures, destination lifecycle, and shutdown while ordinary packet/log sinks remain active.

Exit criterion: tap delivers authorized requests and uniquely associated
responses as format-11 PDUs with exact original RADIUS payloads.

## Phase 6 — Commands, configuration, and operator documentation

Primary locations: `cmd/sniff`, `cmd/hunt`, `cmd/tap`, shared protocol/runtime
configuration, command READMEs, and `docs/manual`.

- [ ] Add thin `lc sniff radius`, `lc hunt radius`, and `lc tap radius` protocol specifications using the shared catalog/runtime patterns; retain `lc process` and existing `lc watch` commands.
- [ ] Expose capture ports, ordinary identity/attribute filters, MAC interpretation, operator line-mapping profiles and scope, transaction expiry/capacity, and supported protocol scope through consistent flags, YAML, and environment binding. Validate incompatible options and bounds; profiles select concrete attributes without querying inventory.
- [ ] Keep X1/X2 configuration in LI build-tagged implementations and no-op stubs. Ensure ordinary RADIUS commands do not require LI or task activation.
- [ ] Expose counters for malformed input, matched requests, correlated/unmatched/ambiguous responses, stale generation rejection, state exhaustion, and X2 encoding/delivery outcomes with documented ownership and units.
- [ ] Document mirrored BRAS/BNG topology, capture-scope/proxy assumptions, sample non-LI and tap POI setups, MDF settings, unsupported transports/messages, no-secret association limits, and independent output enablement.
- [ ] Document NatParas userName/lineID to X1 mappings, supported AVP/VSA encodings and examples, known-line verification, upstream inventory-resolution responsibility, scope uniqueness, conjunctive criteria, and explicit unsupported-form rejection.
- [ ] Update command/config references, structured-log documentation and schema contract, and LI deployment guidance. Label distributed support complete only after Phase 7 passes.

Exit criterion: operators can configure ordinary and LI-enabled capture without
implicit SIP behavior or undocumented identity conventions.

## Phase 7 — Distributed parity and release verification

- [ ] Replay equivalent fixtures through tap and hunt/process and compare target attribution, association status, ordinary outputs, and decoded X2 PDUs, accounting only for documented topology-specific fields.
- [ ] Cover multiple hunters/interfaces, upstream processor forwarding, reconnect/restart scope changes, filter update races, dropped request transport, and legacy/missing evidence. No cross-scope target delivery is permitted.
- [ ] Run the complete acceptance matrix below, targeted unit/integration suites, decoder fuzzing, and race tests for correlator, filter updates, task lifecycle, and queued delivery.
- [ ] Build applicable non-LI variants (`all`, `hunter`, `processor`, `tap`, `cli`, `tui`) and LI variants (`all li`, `processor li`, `tap li`); run `make verify-no-li` and relevant vet checks.
- [ ] Validate against the deployment MDF and representative BRAS traces before claiming production interoperability. Record external validation as pending if the receiver or traces are unavailable.
- [ ] Format changed files before staging, verify each completed task before checking it off, and commit implementation changes together with this updated plan in reviewable increments.

## Acceptance matrix

| Area                 | Required evidence                                                                                                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Decode               | Authentication, accounting, custom ports, IPv4/IPv6, malformed/truncated data, repeated/unknown attributes, and explicit fragment behavior                                                               |
| Identity             | Exact User-Name bytes/case/realm semantics, configured MAC forms, invalid input rejection, NAI mapping exclusively to the RADIUS path in this scope, and explicit SIP URI targets retaining SIP behavior |
| NAI migration        | Persisted/active NAI tasks lose obsolete SIP filters and authorization evidence; restoration/reconciliation cannot recreate the incorrect mapping                                                        |
| X1 AVP subset        | User-Name, NAS-Port-Id, and vendor 3561/type 1 AVPs activate/modify/round-trip/restore/distribute; malformed and unsupported forms fail explicitly                                                       |
| Access-line mapping  | Known-line fixtures verify operator mapping and scope; inventory-only targets require upstream resolution; equal values in unrelated scopes cannot authorize delivery                                    |
| Attribute predicates | Repeated attributes and VSA packing variations match deterministically; every criterion of a compound task must match before attribution                                                                 |
| Correlation          | Tuple/scope separation, Identifier reuse, retransmissions, duplicates, reordering, missing requests, ambiguity, expiry, and capacity pressure                                                            |
| Authorization        | Direct versus inherited evidence, current-generation admission, task modification/deactivation/expiry/reactivation, ID reuse, and multi-task attribution                                                 |
| X2                   | Format 11, exact payload bytes, common attributes, sequence, approved correlation semantics, direction, and queued lifecycle behavior                                                                    |
| Ordinary outputs     | No-LI/no-task operation, text/JSON and TSV/JSONL schemas, PCAP/link type, upstream, TUI, virtual interface, and independence from X2 rejection                                                           |
| Topology             | Equivalent tap and hunt/process attribution/delivery; no cross-hunter/interface association or metadata loss through adapters                                                                            |
| Resource behavior    | Bounded memory/queues, observable drops, no panic/race, shutdown draining, and slow-subscriber isolation                                                                                                 |
| Compatibility        | Additive protobuf evolution, explicit unsupported capability handling, LI/non-LI builds, and existing protocol regression checks                                                                         |

## Dependency and delivery sequence

Phase 1 follows the observation/scope decisions in Phase 0. Phase 2 follows the
identity and association decisions. Phase 3 uses both shared components and is
the ordinary RADIUS milestone. Phase 4 requires the target/migration contract and
transported provenance. Phase 5 requires Phase 4 and the MDF contract and is the
tap POI milestone. Phase 6 can progress alongside integration once interfaces
stabilize. Phase 7 is the distributed-support release gate.

This plan is based on the supplied assessment and a limited local integration
check. Creating it does not verify implementation, execute tests, or establish
MDF interoperability.
