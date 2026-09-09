# RADIUS POI implementation plan

Date: 2026-09-08

Status: Phase 0 local contracts and synthetic acceptance fixtures implemented;
external MDF agreement and production operator mapping verification pending.
Phase 1 shared decoder and observation foundation implemented and verified.
Phase 2 exact filters and bounded transaction association implemented and verified.
Phase 3 capture ingress, transport, and ordinary outputs implemented and verified.
Phase 4 X1 targets and current-generation authorization implemented and verified.
Phase 5 raw RADIUS X2 and local tap POI implemented and verified.
Phase 6 commands, configuration, counters and operator documentation implemented and verified.
Phase 7 remains pending.

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

The local profile is specified in the [identity and target contract](../design/radius-identity-contract.md)
and [observation, association, and MDF acceptance contract](../design/radius-observation-contract.md).
Decoder and ordinary output work can proceed against these contracts. External
operator/MDF acceptance remains a deployment gate; the synthetic profile must
not be represented as receiving-MDF agreement.

- [x] Specify exact User-Name semantics: default to byte-exact, case-sensitive matching with no realm stripping, Unicode normalization, or SIP substring behavior; define how textual X1 values map to bytes and how invalid encodings are rejected or represented.
- [x] Select the subscriber MAC attribute and accepted encodings for the deployment. Make Calling-Station-Id interpretation explicit, reject malformed or decorated values outside the selected convention, and never use mirrored Ethernet addresses as subscriber identity.
- [x] Finalize the required `radiusAttribute` contract: one complete hex-encoded AVP; User-Name, NAS-Port-Id, or a vendor 3561/type 1 VSA containing exactly one target sub-attribute. Validate outer/inner lengths and use exact value-byte matching; reject unsupported types, vendors, malformed encodings, and extra target sub-attributes.
- [x] Establish synthetic operator line-attribute mappings with documentation and known-line fixtures. Define necessary operator/NAS/access-node scope and how it is enforced through dedicated POI deployment or supported conjunctive X1 criteria. Accept explicitly provisioned resolved values; keep inventory lookup upstream and reject unresolved or insufficiently scoped targets.
- [x] Define repeated-attribute matching as an exact matching instance in a fully validated packet; match a VSA target by vendor/type/value regardless of captured sub-attribute grouping. Preserve AND semantics for all criteria within one X1 task and independent ownership across tasks; reject unsupported combinations.
- [x] Define a concrete local MDF acceptance profile for X2 Correlation ID scope, lifetime, request/response reuse, encoding, and Unknown Payload Direction; do not equate correlation with the RADIUS Identifier.
- [ ] Obtain receiving-MDF agreement to that profile. No receiver or service contract has been supplied; local design and wire fixtures do not establish this agreement.
- [ ] Validate production operator MAC/line mappings and isolation against operator documentation and known-line traces. Synthetic mappings and cross-scope fixtures establish the local acceptance convention only.
- [x] Define fragment handling for IPv4 and IPv6. For the initial release, prefer rejecting fragmented datagrams from RADIUS analysis and LI attribution with a counter, while retaining them in independently configured generic packet outputs; require bounded reassembly if fragments must be supported.
- [x] Define timeout and capacity defaults, capture-scope identity across reconnects/restarts, retransmission retention, duplicate delivery policy, and behavior for responses observed before requests. Default to no retroactive inherited authorization without a separately bounded design.
- [x] Record that association without a RADIUS shared secret is observational, not cryptographic authentication; define fail-closed behavior for multiple plausible request instances.
- [x] Create synthetic, non-sensitive PCAP fixtures and expected observations for all six supported message codes, both IP families, accounting/custom ports, multiple clients, and multiple capture scopes. Include expected raw RADIUS payloads for X2 golden checks.

Exit criterion: target mapping, identity semantics, association policy, and MDF
expectations are explicit; unsupported scope is documented rather than accepted
implicitly.

Phase 0 local verification (2026-09-08): the contracts received independent
sub-agent review; identified memory-limit, late-delivery, and fragment issues
were corrected and reviewed by the parent agent. The
[fixture package](../../testdata/radius/README.md) contains 26 PCAP observations
and 21 original RADIUS payload goldens, covering every supported code in both
IP families, custom/accounting ports, clients/scopes, known-line collisions,
VSA grouping, malformed data, and fragments.

```bash
GOCACHE=/tmp/lippycat-go-cache go test ./testdata/radius -count=1
GOCACHE=/tmp/lippycat-go-cache go run ./testdata/radius --check
```

Both checks passed. An additional independent Python wire check verified all
26 records, payload goldens, IPv4/UDP checksums, fragment alignment, and complete
code/family coverage. Changed Markdown and Go files were formatted and
`git diff --check` passed. These checks do not exercise a production RADIUS
implementation. External MDF agreement and operator verification remain the
two unchecked Phase 0 acceptance gates above.

## Phase 1 — Shared decoder and observation model

Primary locations: new `internal/pkg/radius`, `internal/pkg/types`,
`internal/pkg/protocolmeta`, and `internal/pkg/protocolcatalog`.

- [x] Audit the pinned gopacket RADIUS decoder and wrap it with explicit UDP payload decoding for authentication, accounting, and configured ports; do not depend on the default 1812 registration.
- [x] Validate header, declared message length, attribute boundaries, packet truncation, and supported message codes. Preserve the exact validated header, Authenticator, and attribute bytes, including unknown and repeated attributes in wire order.
- [x] Define an observation carrying capture time/scope, endpoints, separate NAS identity fields, original message bytes, decoded attributes, opaque transaction identity, association status, and direct/inherited attribution references with generation information.
- [x] Specify ownership and copying at asynchronous boundaries so capture-buffer reuse cannot change observations or packet payloads; avoid making non-LI packages depend on LI implementation types.
- [x] Implement explicit outcomes for malformed, unsupported, fragmented, unmatched, and ambiguous observations, with one counter owner per outcome.
- [x] Add unit tests and bounded fuzz runs for decoder length handling, unknown/repeated attributes, malformed vendor attributes, truncation, and arbitrary input; verify no panic or false identity extraction.

Exit criterion: valid packets produce stable byte-preserving observations and
invalid input cannot enter target attribution.

Phase 1 verification (2026-09-09): implemented the shared foundation in
`internal/pkg/radius`. The pinned gopacket audit, explicit UDP/IP validation,
owned observations, scope/epoch IDs, grouped generation-bearing evidence, and
counter ownership are documented in the [package README](../../internal/pkg/radius/README.md).
Valid observations start with `unprocessed` association status; unmatched and
ambiguous statuses are defined, while their decisions and counters belong to
the Phase 2 correlator. No decoder rejection exposes message attributes, NAS
identity or attribution evidence.

The foundation remains in a single non-LI package. Shared display/protobuf
adapters in `types`/`protocolmeta` and capability registration in
`protocolcatalog` are deferred to Phases 3/6; registering command/filter support
now would advertise capabilities not yet implemented.

Specialized sub-agents implemented decoder and observation components, and an
independent reviewer checked their integration. Parent review verified the
changes and fixed acceptance of malformed IPv4/IPv6 option boundaries with
regression tests. All 26 committed PCAP observations match expected validation,
endpoints, ordered attributes and raw payload goldens; mutation checks verify
capture-buffer independence. Tests cover deep-cloned evidence, concurrent epoch
IDs/counters, sequence exhaustion, all six codes, unknown/repeated AVPs, malformed
vendor data, custom ports, truncation and fragment precedence.

```bash
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all ./internal/pkg/radius ./internal/pkg/protocolmeta ./internal/pkg/protocolcatalog ./internal/pkg/types ./testdata/radius -count=1
GOCACHE=/tmp/lippycat-go-cache go test ./internal/pkg/radius -run '^$' -fuzz '^FuzzDecode$' -fuzztime=10s -parallel=2
GOCACHE=/tmp/lippycat-go-cache go test ./internal/pkg/radius -run '^$' -fuzz '^FuzzDecodePacket$' -fuzztime=15s -parallel=2
GOCACHE=/tmp/lippycat-go-cache go vet ./internal/pkg/radius
GOCACHE=/tmp/lippycat-go-cache go run ./testdata/radius --check
```

All checks passed. Payload fuzzing completed 270,099 executions; the final packet
fuzz run completed 253,407 executions after the option-validation fixes. Go and
Markdown files were formatted before staging. Phase 0 external MDF/operator
acceptance gates remain pending and do not block this decoder foundation.

## Phase 2 — Exact filters and bounded transaction association

Primary locations: `internal/pkg/radius`, `internal/pkg/filtering`,
`internal/pkg/hunter/application_filter.go`, `api/proto/management.proto`,
and filter management/capability adapters.

- [x] Add ordinary RADIUS User-Name, subscriber MAC, and required-subset attribute filters with exact matchers, validation, serialization, and CLI management support. Reuse the AVP predicate implementation for ordinary and X1-derived filters while keeping authorization separate.
- [x] Implement structured AVP/VSA predicates and compound task criteria with scope binding. Preserve target kind, criterion grouping, and operator/NAS scope through filter distribution; never authorize a conjunctive task from one independently matched filter ID.
- [x] Extend protobuf enums additively without reusing field or enum numbers, regenerate bindings using repository tooling, and update distribution, supported-filter reporting, persistence, and display conversions.
- [x] Define behavior for older hunters/processors: unsupported RADIUS filters or missing required provenance must not silently degrade to broader LI matching. Test capability rejection and ordinary raw-packet compatibility.
- [x] Implement a concurrent bounded correlator keyed by capture scope, client/server IP and UDP ports, and Identifier, retaining request code, Authenticator, request-instance identity, matches, and filter/task generations.
- [x] Enforce compatible request/response code families. Distinguish retransmissions from distinct request instances, including same-Identifier reuse, and avoid overwriting competing candidates into a false unique match.
- [x] Define safe candidate retention after ambiguity, expiration, and capacity pressure so losing state cannot make a known competing request appear uniquely authorized; use bounded suppression/tombstone state or an equivalent conservative policy.
- [x] Keep direct attribute matches separate from inherited matches. Inherit only from a unique eligible request; preserve multiple target/task references on that request without combining competing owners.
- [x] Implement expiry, hard memory/candidate limits, cleanup/shutdown, and counters for collisions, ambiguity, expiration, and capacity loss. Ensure nonmatching competing requests participate in ambiguity detection.
- [x] Test simultaneous tuples/scopes, Identifier wrap/reuse, retransmissions, duplicate mirrors, reversed/reordered traffic, absent requests, incompatible codes, eviction, and concurrent filter changes with an injectable clock.
- [x] Test exact User-Name/NAS-Port-Id/Agent-Circuit-Id matches, malformed target hex and nested lengths, unsupported types/vendors, repeated attributes, VSA grouping variations, partial compound matches, and identical line values under different NAS/operator scopes.

Exit criterion: deterministic association is bounded in memory and never grants
inherited attribution from missing, ambiguous, or stale evidence.

Phase 2 verification (2026-09-09): specialized sub-agents implemented the
shared predicates, correlator and management/distribution adapters. The parent
reviewed the integrated changes and added a committed-PCAP acceptance test;
independent cross-review found and corrected stale ordinary inheritance,
callback storage aliasing, revision reuse, scope serialization and restoration
failure behavior. All six message codes, both families and custom ports pass
the shared fixture pipeline with exact packet/message byte preservation and
operator-scoped line matching.

The correlator bounds candidates, evidence bytes, guards and total charged
state; lost state suppresses inheritance conservatively, including unmatched
competitors. Injectable time, concurrent revision changes, Identifier wrap,
retransmissions, duplicate responses, missing/reordered requests, expiry,
per-key/total pressure, global suppression, callback mutation and shutdown are
covered. Every inherited reference requires a current-generation callback;
processor-side task admission remains Phase 4 work.

Management enum values 18–21 and structured scope/criteria are additive.
Filter-file serialization uses explicit snake_case fields and rejects misspelled
RADIUS fields and invalid restoration. Positive revisions, compound revision
consistency and bounded same-process deletion history prevent stale ordinary
filter evidence from becoming current again. Management restart requires a
fresh capture epoch and correlator, consistent with the existing scope contract.
The [package README](../../internal/pkg/radius/README.md) documents these APIs,
configuration limits, CLI examples and the compound file format.

Version-1 RADIUS filter capability and the exact type string are both required
for distribution. Explicit legacy targets and local tap targets reject RADIUS
filters; current hunters do not advertise the version until Phase 3 provides
capture ingress and provenance transport. The application-filter observation
adapter is implemented and tested independently; it never places RADIUS
attribution into the generic LI filter-ID path. Raw packet transport remains
compatible without RADIUS metadata. These are Phase 2 foundations, not a claim
that live RADIUS capture, tap POI or distributed LI are complete.

```bash
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all ./internal/pkg/radius ./internal/pkg/filtering ./internal/pkg/hunter ./internal/pkg/hunter/connection ./internal/pkg/processor/filtering ./internal/pkg/tui/components/filtermanager ./internal/pkg/tui/components ./cmd/filter ./testdata/radius -count=1
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all ./internal/pkg/filterclient -count=1
GOCACHE=/tmp/lippycat-go-cache go vet -tags 'all li' ./internal/pkg/radius ./internal/pkg/filtering ./internal/pkg/hunter ./internal/pkg/processor/filtering ./cmd/filter ./internal/pkg/tui/components/filtermanager ./internal/pkg/tui/components
```

These checks passed. Filter-client tests required approved execution outside the
sandbox for local gRPC sockets. Builds passed with `all`, `hunter`, `tap`,
`all li` and `processor li`; CLI smoke checks confirmed RADIUS help and explicit
MAC-profile validation. Changed Go/Markdown files were formatted and
`git diff --check` passed. Phase 0 external MDF/operator gates remain pending.

Phase 2 follow-up assessment (2026-09-09): three sub-agents reviewed correlation,
matching and management against the plan and contracts. Parent verification
reproduced two filter-replacement defects: incompatible hunters retained the
previous filter when a global filter changed to RADIUS, and capable hunters did
not restart capture when a RADIUS filter replaced BPF. Distribution now removes
obsolete filters using their previous type, and hunter updates refresh application
matchers and account for the installed BPF type before replacement. Regression tests cover legacy peers,
RADIUS capability differences, target scope changes and idempotent capture
restart. No additional matcher or correlator defects were confirmed.

The Phase 2 race suite listed above passed during assessment. After fixes,
the full processor filtering and hunter/filtering, hunter and hunter/capture
race suites passed, as did vet for the changed packages with `all li`.
Independent cross-review checked the fixes; Go/Markdown formatting and
`git diff --check` passed.

Phase 2 second assessment (2026-09-09): three sub-agents reviewed correlation,
predicates and management against the plan and contracts. Parent verification
confirmed two remaining management defects. Concurrent mutations could deliver
revision 3 before revision 2, resurrect a deleted filter, or delete a newly
recreated filter. A dedicated mutation lock now preserves commit, distribution
and persistence order while allowing callbacks to read filter state. The CLI
also discarded explicit `--revision` when replacing RADIUS with another filter
type; it now preserves that flag and documents its use for replacements.

Parent-run regressions failed without each fix and passed with the fixes.
Ordering coverage includes modify/modify, modify/delete and delete/recreate;
the CLI regression sends a BPF replacement through a local gRPC server into the
real filter manager. The existing concurrent-send test now consumes updates and
asserts every delivery, avoiding serialized queue timeouts already covered by
the separate timeout test. No additional predicate or correlator defects were
confirmed. Live ingress and LI admission remain assigned to later phases.

The full Phase 2 race suite above passed before changes. After fixes, race tests
passed for processor filtering, hunter filtering, hunter, filterclient and the
CLI replacement regression. Vet passed for changed packages with `all li`.
Local gRPC tests used approved execution outside the sandbox. The plan's Phase 2
completion status remains unchanged.

Phase 2 third assessment (2026-09-09): three sub-agents reviewed correlation,
predicates and management; parent review confirmed a local tap capability gap
in both management RPC paths. `UpdateFilter` stored, persisted and distributed
RADIUS filters before local rejection, while local `UpdateFilterOnProcessor`
requests bypassed that rejection and reported success. Both paths now check
local RADIUS capability before manager mutation. Scoped requests perform this
check only after routing identifies the local processor.

Parent-run regressions reproduced the defect for creation and BPF replacement
through both RPCs. They verify rejection leaves manager/local policy, persisted
bytes, hunter update queues and available revisions intact. Independent
cross-review verified the fix. Positive regression cases confirm ordinary
processors still accept and distribute RADIUS filters through both RPCs.
No additional predicate or correlator defects
were confirmed; live ingress and LI admission remain later-phase work.

The Phase 2 race suite passed before changes. After the fix, the full processor
and processor-filtering race suites passed, along with the new regressions under
`tap` and `processor li` tags and processor vet under `all li`. Network tests
used approved execution outside the sandbox. Go/Markdown formatting and
`git diff --check` passed. Phase 2 completion status remains unchanged.

## Phase 3 — Capture ingress, transport, and ordinary outputs

Primary locations: `internal/pkg/hunter/forwarding/manager.go`,
`internal/pkg/processor/source/local.go`, `internal/pkg/pipeline/captureadapter`,
`internal/pkg/pipeline/grpcadapter`, `api/proto/data.proto`,
`internal/pkg/processor`, `internal/pkg/events`, `internal/pkg/logschema`,
`internal/pkg/logstream`, and the sniff/TUI presentation paths.

- [x] Invoke the shared decoder/matcher/correlator before the hunt forwarding and tap local-source unmatched-packet gates. Include both directions in BPF generation and preserve visibility of competing requests needed for safe correlation.
- [x] Extend the normalized packet envelope and protobuf metadata with RADIUS observations and provenance as needed; preserve capture scope, timestamp, link type, bytes, and attribution through local, gRPC, and upstream forwarding adapters.
- [x] Define trusted provenance boundaries and validate envelope consistency against captured bytes. Do not treat a transported filter ID alone as proof of a RADIUS transaction association.
- [x] Keep RADIUS handling protocol-neutral at `lc process`; integrate analyzer selection and protocol detection without requiring a separate processor command or an X1 task.
- [x] Add shared RADIUS display metadata, protocol summaries, and existing watch/TUI rendering support; expose decoded observations through sniff text/JSON conventions.
- [x] Add typed RADIUS observation events and a canonical `radius` log schema with versioned fields/types, transaction/association status, and documented attribute representation. Integrate TSV/JSONL encoding, rotation, configuration, and schema golden fixtures.
- [x] Document and test which attributes are exposed in text/log outputs, particularly credential-bearing and binary values; retain byte preservation for explicitly configured packet/X2 sinks without blindly dumping every raw attribute into routine summaries.
- [x] Verify unified/rotating PCAP, upstream forwarding, subscriber broadcast, and virtual-interface injection retain their existing behavior. Do not route RADIUS through per-call VoIP writers.
- [x] Verify independent sink enablement, bounded queues, overflow counters, graceful draining, and subscriber isolation; slow TUI clients must not drive hunter flow control.

Exit criterion: non-LI capture and filtering work with useful metadata and all
supported ordinary outputs, including identity-free correlated responses.

Phase 3 verification (2026-09-09): specialized sub-agents implemented capture
integration, transport/provenance, and typed logs; the parent reviewed and tested
those changes. Independent cross-review found and corrected envelope refresh
losing observations/restoring generic IDs, legacy interface-scope collisions,
local filter mutation ordering, IPv6 extension-byte detection, and rejected
packet timestamps advancing expiry. Dedicated fixtures cover those regressions.

Hunt/tap observe competitors before selection and retain identity-free uniquely
associated responses. Dynamic BPF includes both directions of configured service
traffic; the broader IPv6 protocol-chain branch receives userspace validation.
Capture changes create fresh epochs and exclude queued pre-boundary packets from
association. Local capability requires an installed source and matcher. Routine
summaries use an explicit attribute allowlist with hex encoding; credentials,
authenticators and unknown values remain absent. Sniff logs/CLI share observations.
The version-1 `radius` schema has field/type and TSV/JSONL golden coverage.

Parent-run fixture integration verifies unified and rotating PCAP bytes/timestamps,
subscriber output, identity-free association, and exclusion from VoIP per-call
files. Separate tests exercise real upstream queue/wire transport and mock virtual
interface injection. RADIUS log rotation/draining and independent stream selection
pass; shared dispatcher/logstream overflow tests pass. A full slow RADIUS
subscriber queue records drops without throttling hunters. Local and remote watch
and sniff text/JSON tests cover safe binary values and credential omission.

```bash
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all ./internal/pkg/radius ./internal/pkg/pipeline/... ./internal/pkg/hunter/... ./internal/pkg/processor/... ./internal/pkg/events ./internal/pkg/logschema ./internal/pkg/logstream/... ./internal/pkg/capture ./internal/pkg/detector ./internal/pkg/remotecapture ./internal/pkg/tui/... ./cmd/sniff ./cmd/tap ./cmd/process -skip '^TestComprehensivePcapDetection$'
GOCACHE=/tmp/lippycat-go-cache go test -race -tags 'all li' ./internal/pkg/radius ./internal/pkg/pipeline/... ./internal/pkg/processor ./cmd/sniff ./cmd/tap -run 'RADIUS|Radius' -count=1
```

Both suites passed, as did targeted final capture/detection/presentation tests and
vet for the changed package trees with `all li`. All nine applicable non-LI/LI
variants (`all`, `hunter`, `processor`, `tap`, `cli`, `tui`, `all li`, `processor li`,
`tap li`) built successfully. Network tests and Go module-cache updates used
approved execution outside the sandbox. The unfiltered detector suite cannot pass
because its existing comprehensive test requires absent `http.pcap`, `tls.pcap`,
`dns.pcap` and `rtp.pcap` fixtures; only that unrelated test was excluded above.

This is the ordinary-output milestone. Dedicated commands/configuration remain
Phase 6; X1/current task admission and X2 encoding remain Phases 4/5. Transported
claims are byte-validated, not proof of origin trust or authorization, and cannot
enter generic LI filter-ID admission. Legacy raw observations have no inherited
authorization. Distributed reconnect/snapshot convergence and release parity remain
Phase 7; external MDF/operator acceptance gates remain pending. Dynamic RADIUS
BPF can expand beyond base BPF, so operator/NAS isolation must not rely on that
capture expression. See the package README for runtime and provenance details.

### Phase 3 post-implementation audit (2026-09-09)

Three specialized reviewers compared ingress, transport/provenance and ordinary
outputs against the plan. Parent review independently reproduced two ingress
defects that the original adapter-level tests did not cover:

- [x] Prevent requests captured while old handles drain from seeding the next
      capture epoch. Tap now establishes its boundary after old readers finish;
      hunter stops and waits before publishing the boundary and starting replacement
      capture. A timed-out hunter restart opens no replacement generation. The shared
      external-consumer capture function now waits for reader completion rather than
      returning immediately because no processor callback was supplied.
- [x] Preserve original fragments through the actual capture loop. Previously an
      incomplete IPv4 fragment disappeared, while an IPv6 atomic fragment was rebuilt
      and accepted as an ordinary RADIUS request. Generic capture now preserves
      fragments; explicit VoIP capture retains IP reassembly. VoIP hunter/tap modes
      exclude RADIUS filtering capability, and live watch follows its selected mode.
      Actual-loop regressions retain all 26 acceptance records, reject incomplete
      IPv4 and atomic IPv6 fragments, and cover default/custom ports, reversed
      fragment arrival, validation counters and explicit VoIP reassembly.

No additional transport/provenance, safe presentation, schema/logging or sink
defect was confirmed. The package README's stale Phase 1/2 introduction was
corrected. Dedicated commands, X1/X2 admission and distributed snapshot convergence
remain in their explicitly deferred phases.

Parent-run regressions reproduced both defects before fixes, and independent
cross-review verified the final changes. Full race suites passed for capture,
hunter, local source, pipeline, RADIUS, events, schema/logstream, TUI and sniff.
Targeted `all li` regressions passed for processor trees, detection, remote display,
tap and VoIP. Vet passed for changed package trees with `all li`; all nine
non-LI/LI build variants listed above built successfully. Build commands emitted
a nonfatal read-only module-stat-cache warning but exited successfully. The known
missing detector fixtures were not needed by these focused detector checks.

## Phase 4 — X1 targets and current-generation authorization

Primary locations: `internal/pkg/li` target types, filters, registry, manager,
restoration/reconciliation paths, and `internal/pkg/li/x1` capabilities and
target conversions. Read the LI package instructions before implementation.

- [x] Correct X1 `nai` mapping to the dedicated RADIUS User-Name filter and implement exact MAC target mapping. Keep SIP URI targets mapped to SIP filters, with no NAI-to-SIP fallback or VoIP dependency; keep unsupported attribute forms rejected.
- [x] Update target string representations, bidirectional X1 conversion, activation/modification validation, capability reporting, ADMF reconciliation, persisted restoration, and registry validation together.
- [x] Support the required AVP subset through all X1 lifecycle and round-trip paths, including hex-binary serialization and subset-aware capability/validation behavior. Preserve conjunctive criteria and current-generation scope evidence for direct requests and inherited responses; reject unsupported AVPs/combinations explicitly.
- [x] Apply the migration policy to existing NAI tasks and their distributed filters, including reconnect/restoration paths. Test that obsolete SIP filters and queued authorization cannot survive correction and that explicit SIP URI targets continue to work.
- [x] Document the corrected NAI mapping and migration behavior for operators, including the requirement to use explicit SIP URI targets for SIP filtering.
- [x] Reject RADIUS task requests for X3 or combined delivery; accept only the supported X2 service/profile and valid destination configuration.
- [x] Extend distributed filter evidence with the generation binding required for RADIUS. Define how capture-side filter revisions map to authoritative task generations, including updates racing packet transport.
- [x] Add RADIUS-specific provenance validation before the current non-RTP direct/inherited union can authorize delivery; verify direct matches and inherited transaction evidence separately.
- [x] Reuse `AcquireTaskAdmission`, activation generations, delivery metadata, and destination lifecycle safeguards. Reject stale evidence after modify, deactivate, expire, restore, and reactivate events, even when filter IDs are reused.
- [x] Test multiple tasks matching one valid request, removal of one owner, stale queued packets, destination changes, and generation changes between initial matching and delivery admission; ordinary outputs must remain unaffected by rejection.

Exit criterion: only current authorized tasks can admit RADIUS X2 delivery;
stale or ambiguous inherited references cannot bypass validation.

Phase 4 verification (2026-09-09): specialized sub-agents implemented X1 target
handling, scoped compound filters, and processor admission. The parent reviewed
the combined changes, exercised the real processor filter store, and requested
independent cross-review. NAI now matches exact RADIUS User-Name exclusively;
MAC and the required AVP subset preserve their identity and bytes through X1,
ADMF, registry and filter distribution. Unsupported mixed targets, service scope,
X3/combined delivery and conflicting mediation profiles are rejected. Explicit
StartTime changes that the modification model cannot represent are rejected.

One compound filter owns the complete task conjunction. Its task, filter and
criterion generations track authoritative activation generations, including
destination and timing modifications. Current admission revalidates captured
bytes, source/scope, complete direct predicates and unique inherited references.
Tests cover multiple owners, partial matches, stale queued observations,
reactivation with reused IDs, modification between matching and final admission,
expiry checks, and ordinary-output independence. Generic SIP/RTP IDs and the
proprietary metadata sink cannot authorize RADIUS; spurious SIP display metadata
cannot send admitted RADIUS observations through the SIP encoder.

Migration withdraws obsolete full and short filter IDs before startup, preserves
generation watermarks, and requires fresh authorization after restart. Persisted
RADIUS product is never replay-authorized. Pending legacy NAI tasks cannot
promote automatically; retained failed/deactivated legacy identities remain
inactive. Reconciliation revokes invalid replacements before remote cleanup,
including malformed ADMF targets, unsupported scheduling, missing destinations
and failed enforcement updates. Real filter-manager tests caught and corrected
nonexistent-ID withdrawal and duplicate cleanup during restoration. Legacy
migration without filter inventory fails closed. Operator migration and scope
configuration are documented in [LI integration](../LI_INTEGRATION.md).

Local tap batches establish their capture origin internally. Direct remote
admission requires a verified mTLS certificate identity matching the batch hunter
ID and observation origin; the trust marker is never serialized. Insecure,
server-only TLS and unverified relay sources retain ordinary outputs but cannot
admit RADIUS LI. The existing Phase 7 relay/reconnect/snapshot gate remains open.
Phase 5 still owns format-11 encoding, sequencing/correlation allocation and
MDF integration; Phase 4 does not claim RADIUS PDU delivery.

Parent-run final validation:

```bash
GOCACHE=/tmp/lippycat-go-cache go test -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/radius ./internal/pkg/pipeline/... ./internal/pkg/hunter/... -count=1
GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/li ./internal/pkg/processor ./internal/pkg/processor/source ./internal/pkg/radius -run 'RADIUS|Radius|Metadata' -count=1
GOCACHE=/tmp/lippycat-go-cache go vet -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/radius ./internal/pkg/pipeline/...
```

All checks passed. All nine applicable variants (`all`, `hunter`, `processor`,
`tap`, `cli`, `tui`, `all li`, `processor li`, `tap li`) built successfully.
Network integration tests used approved execution outside the sandbox; builds
emitted only the known nonfatal read-only module-stat-cache warning. Changed Go
and Markdown files were formatted, and `git diff --check` passed. External
MDF/operator acceptance and Phase 5 raw RADIUS X2 and local tap POI implemented and verified.
Phases 6–7 remain pending.

## Phase 5 — Raw RADIUS X2 encoding and tap POI

Primary locations: `internal/pkg/li/x2x3`,
`internal/pkg/processor/processor_li.go`, and the LI packet ingress path.

- [x] Add a RADIUS encoder consuming an attributed observation without requiring VoIP metadata or Call-ID and without owning matching/correlation state.
- [x] Use `PayloadFormatRADIUS = 11` and the original bytes bounded by validated RADIUS Length; exclude Ethernet/IP/UDP and padding, and never reconstruct payload from decoded attributes.
- [x] Reuse common PDU attributes, shared sequencing, capture timestamps, endpoint metadata, approved Correlation ID semantics, and queued TLS X2 delivery; keep subscriber-relative direction unknown unless justified.
- [x] Dispatch RADIUS separately from SIP packet IRI and proprietary normalized metadata delivery. Verify ingress reaches RADIUS provenance validation before generic LI filter-ID handling can discard or admit it incorrectly.
- [x] Add golden PDU tests for all supported exchanges, repeated/unknown attributes, non-VoIP observations, byte identity, format, sequencing, correlation, direction, timestamps, and endpoint attributes.
- [x] Run tap fixture integration against a local test MDF receiver; test delivery pressure, encoder failures, destination lifecycle, and shutdown while ordinary packet/log sinks remain active.

Exit criterion: tap delivers authorized requests and uniquely associated
responses as format-11 PDUs with exact original RADIUS payloads.

Phase 5 verification (2026-09-09): specialized sub-agents implemented the
stateless encoder, dedicated processor callback and local MDF integration tests.
The parent implemented durable correlation allocation, reviewed every component,
and requested independent cross-review of allocation, encoding and integration.
All six supported message codes have complete independently packed PDU goldens
(21 vectors), including IPv4/IPv6, custom ports and repeated/unknown attributes.
Tests verify original message bytes, capture time, endpoints, format 11, Unknown
direction, shared sequencing, concurrent encoding and buffer independence.

Correlation ranges are atomically persisted and synced before use, with exclusive
state ownership, restart range skipping and no wrap. Bounded allocations reuse
request instances across task XIDs and reject expired, inconsistent or
capacity-lost allocations. Tests cover request/response and orphan reuse, scope
isolation, concurrent allocation, byte/count limits, corrupt storage, persistence
failure, restart and subprocess lock contention. Cleanup is throttled to one
sweep per second. The processor uses its configured identity for NFID/IPID and
requires durable storage; missing storage fails closed for X2. State configuration
and multi-encoder identity constraints are documented in
[LI integration](../LI_INTEGRATION.md#raw-radius-x2-delivery).

The integration harness runs synthetic request/response fixtures through the
shared local capture processor, protobuf adapter and actual processor batch path
to a mutual-TLS MDF receiver. It verifies exact payloads, exchange correlation,
sequence and shutdown draining with broadcast, PCAP and RADIUS JSON logs active.
Additional tests cover queue overflow, destination transport removal, exhausted
encoder capacity, stale task generations and stopped delivery. Destination tests
exercise the shared transport lifecycle methods; they do not start an X1 server.
Existing X1 and delivery lifecycle regression suites also pass.

Parent-run final validation:

```bash
GOCACHE=/tmp/lippycat-go-cache go test -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/radius -count=1
GOCACHE=/tmp/lippycat-go-cache go vet -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/radius
```

All checks passed, as did all nine builds (`all`, `hunter`, `processor`, `tap`,
`cli`, `tui`, `all li`, `processor li`, `tap li`). Network tests used approved
execution outside the sandbox. Builds emitted only the previously documented
nonfatal read-only module-stat-cache warning. Changed Go/Markdown files were
formatted and `git diff --check` passed before staging.

This completes the local synthetic tap POI milestone. Receiving-MDF agreement
and production operator traces remain external acceptance gates. Dedicated
commands/configuration and distributed release parity remain Phases 6/7; no
production interoperability or distributed completion is claimed.

Phase 5 assessment follow-up (2026-09-09): three specialized sub-agents compared
the encoder, durable correlation allocator and tap delivery path with this plan.
The parent verified their findings. Independent parsing of all 21 PDU goldens
found no wire-format defects, and the correlation implementation matched the
local contract. The review reproduced an authorization gap: expired tasks could
enqueue X2 before the registry expiry sweep. Allocation and encoding also held
the lifecycle admission barrier, delaying task changes until after enqueue.

- [x] Enforce expiration at task admission while preserving the existing implicit-deactivation policy.
- [x] Release preliminary admission before allocation/encoding and reacquire it immediately before RADIUS queue admission; verify expiry, deactivation and modification during allocation suppress X2 while broadcast, PCAP and JSON logs continue.
- [x] Fix the independently discovered default processor filter teardown bug after explicit authorization: avoid updating/deleting the same manager twice through its HunterTarget, while preserving separate local target operations. Verify single distributed notifications and local BPF installation/removal.

The parent reproduced the original expired-task failure (two queued PDUs),
reviewed the fixes and obtained independent cross-review. Full LI, processor and
RADIUS race suites passed across the audit runs, with the processor suite rerun
successfully after the teardown fix. The additional admission-policy regression,
non-LI RADIUS tests and relevant LI/processor/RADIUS vet checks passed. The
`all li`, `processor li` and `tap li` binaries built successfully, with only the
known nonfatal module-stat-cache warning. External MDF/operator acceptance and
the Phase 6/7 gates remain pending.

## Phase 6 — Commands, configuration, and operator documentation

Primary locations: `cmd/sniff`, `cmd/hunt`, `cmd/tap`, shared protocol/runtime
configuration, command READMEs, and `docs/manual`.

- [x] Add thin `lc sniff radius`, `lc hunt radius`, and `lc tap radius` protocol specifications using the shared catalog/runtime patterns; retain `lc process` and existing `lc watch` commands.
- [x] Expose capture ports, ordinary identity/attribute filters, MAC interpretation, operator line-mapping profiles and scope, transaction expiry/capacity, and supported protocol scope through consistent flags, YAML, and environment binding. Validate incompatible options and bounds; profiles select concrete attributes without querying inventory.
- [x] Keep X1/X2 configuration in LI build-tagged implementations and no-op stubs. Ensure ordinary RADIUS commands do not require LI or task activation.
- [x] Expose counters for malformed input, matched requests, correlated/unmatched/ambiguous responses, stale generation rejection, state exhaustion, and X2 encoding/delivery outcomes with documented ownership and units.
- [x] Document mirrored BRAS/BNG topology, capture-scope/proxy assumptions, sample non-LI and tap POI setups, MDF settings, unsupported transports/messages, no-secret association limits, and independent output enablement.
- [x] Document NatParas userName/lineID to X1 mappings, supported AVP/VSA encodings and examples, known-line verification, upstream inventory-resolution responsibility, scope uniqueness, conjunctive criteria, and explicit unsupported-form rejection.
- [x] Update command/config references, structured-log documentation and schema contract, and LI deployment guidance. Label distributed support complete only after Phase 7 passes.

Exit criterion: operators can configure ordinary and LI-enabled capture without
implicit SIP behavior or undocumented identity conventions.

Phase 6 verification (2026-09-09): specialized sub-agents implemented the
thin protocol commands/shared configuration, runtime plumbing/counters and
operator documentation. The parent implemented LI-only configuration and
reviewed all components; independent cross-review found and corrected tap
origin identity validation and X2 correlation lifetime configuration. Tap LI
requires explicit capture/authorization scope agreement, matching transaction
timeouts and durable correlation storage. Its origin is the processor ID plus
`-local`; X2 NFID/IPID remain the processor ID.

All three ordinary commands share exact conjunctive criteria, MAC convention,
resolved line profiles, ports, bounded transaction settings and strict
flags/YAML/environment validation. Static ordinary groups survive dynamic
filter updates; independent dynamic groups can also select traffic. Dedicated
commands reject invalid or unrelated packets after bounded observation, while
generic packet capture keeps its existing output behavior. Counter summaries
identify capture epochs and distinguish validation, association, stale owner
references, state loss, encoding and queue outcomes from actual transport
statistics.

Parent CLI tests verified matching requests and identity-free responses, exact
case/realm behavior, MAC/profile rejection, scoped NAS-Port-Id and
Agent-Circuit-Id, conjunctive rejection, custom ports and flags over environment
over YAML. A real combined-binary output check found shared log flags bound to
another command; active RADIUS command rebinding and regressions fix this.
Configured sniff logs now consume the same observation after selection, with no
second decoder/correlator or duplicate validation counters. The final CLI smoke
produced two JSON packet records, two RADIUS JSONL records and byte-identical
selected PCAP packet data simultaneously. Custom-port configured logging has
additional regression coverage.

Parent-run validation:

```bash
GOCACHE=/tmp/lippycat-go-cache go test -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/hunter/... ./internal/pkg/radius ./internal/pkg/radiusconfig ./internal/pkg/protocolcatalog
GOCACHE=/tmp/lippycat-go-cache go test -race -tags 'all li' ./cmd ./cmd/sniff ./cmd/hunt ./cmd/tap ./cmd/process ./internal/pkg/logflags
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all ./cmd ./cmd/sniff ./cmd/hunt ./cmd/tap ./cmd/process ./internal/pkg/radiusconfig ./internal/pkg/logflags ./internal/pkg/protocolcatalog ./internal/pkg/radius
GOCACHE=/tmp/lippycat-go-cache go vet -tags 'all li' ./cmd/sniff ./cmd/hunt ./cmd/tap ./cmd/process ./internal/pkg/radiusconfig ./internal/pkg/radius ./internal/pkg/logflags ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/hunter/...
GOCACHE=/tmp/lippycat-go-cache make verify-no-li
mdbook build docs/manual --dest-dir /tmp/radius-phase6-smoke/manual
```

All checks passed. All nine applicable variants (`all`, `hunter`, `processor`,
`tap`, `cli`, `tui`, `all li`, `processor li`, `tap li`) built successfully.
An additional unstripped-binary symbol inspection confirmed LI manager/registry,
X2 encoder and LI configuration resolver exclusion. TLS/gRPC integration tests
used approved execution outside the sandbox. Builds emitted only the known
nonfatal read-only module-stat-cache warning. Changed Go/Markdown files were
formatted and `git diff --check` passed before staging.

The [operator guide](../RADIUS.md), manual chapter, command/config references,
structured-log/schema documentation and LI deployment guide describe exact
identity conventions, NatParas mapping, isolated BRAS/BNG mirroring, counters,
independent outputs and unsupported forms. This completes Phase 6. Phase 7
remains the distributed release gate; production operator traces and receiving-MDF
agreement remain external acceptance gates.

## Phase 7 — Distributed parity and release verification

- [ ] Replay equivalent fixtures through tap and hunt/process and compare target attribution, association status, ordinary outputs, and decoded X2 PDUs, accounting only for documented topology-specific fields.
- [ ] Cover multiple hunters/interfaces, upstream processor forwarding, reconnect/restart scope changes, filter update races, dropped request transport, and legacy/missing evidence. No cross-scope target delivery is permitted.
- [ ] Fix and regression-test registration/subscription filter snapshot reconciliation before claiming distributed RADIUS support. Reproduced in the shared hunter filter manager: registration installs revision 1, the filter changes to revision 2 before subscription, and the subscription snapshot sends `UPDATE_ADD`; the hunter ignores the existing ID and retains revision 1. Check deletions during the same gap and snapshot/live-update ordering as well. Verify convergence to current processor policy without retaining stale revisions or deleted filters, including reconnects and legacy-peer compatibility. Relevant paths: `internal/pkg/hunter/filtering/manager.go` (`SetInitialFilters`, `handleUpdate`) and `internal/pkg/processor/processor_grpc_handlers.go` (`SubscribeFilters`). This pre-existing shared-infrastructure concern was reproduced during Phase 2 review; Phase 3 now supplies live ingress capability; snapshot convergence remains unverified until this Phase 7 task passes.
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

The initial plan was based on the supplied assessment and a limited local
integration check. Phase 0 verification is recorded above; it validates design
inputs and fixture integrity, not the future runtime or MDF interoperability.
