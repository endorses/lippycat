# Generalized dynamically learned capture rules

Date: 2026-10-19

Status: implementation verified. All feature and verification tasks are complete;
the final commit task remains pending until the changes are committed.

Baseline: `main` at `69c89acc`. Design source:
[Generalized dynamically learned capture rules](../research/generalized-dynamically-learned-capture-rules.md).

## Outcome

Extract the working distributed media-selection machinery into a shared learned
capture-rule engine. VoIP becomes its first production adapter and retains its
existing capture, attribution, local tap, and LI behavior. Other adapters can use
the engine without importing SIP, inventing a Call-ID, or requiring an LI task.

The first implementation supports exact UDP/TCP transport endpoints with explicit
direction and registered packet qualifiers. A test-only diagnostic adapter proves
that a different subject lifetime can use the actual distributed and local paths.
RADIUS and other future adapters can add their own evidence interpretation and
selector capabilities through the same contracts.

| Deliverable | Observable result |
| --- | --- |
| Shared binding lifecycle | Subject-neutral bindings receive bounded snapshots, revisions, expiry, withdrawal, and effective installation reporting. |
| Typed matching | Exact endpoints retain transport, direction, domain, and qualifier semantics through distribution and installation. |
| VoIP adapter | Existing SIP learning, RTP/RTCP qualification, call resolution, and signaling continuity run through the common engine. |
| Shared hunter/tap runtime | The same adapter and matcher work remotely and locally; generic runtime construction does not require VoIP mode. |
| Compatible transport and evidence | Existing media clients and stored proofs retain their meanings; new evidence is explicitly typed and negotiated. |
| LI integration | Current task authority, media grants, original signatures, producer validation, and delivery checks remain enforced. |
| Independent adapter demonstration | An unqualified UDP/TCP diagnostic binding works without SIP, call-registry, or LI identity. |

This delivery establishes the reusable mechanism. Additional protocol trackers,
IP/prefix selectors, and full flow-tuple selectors are added when their concrete
adapters require them; they are not represented as currently supported matches.

## Architectural decisions

### Common engine and adapter ownership

Use these responsibilities and package boundaries. New files are named for their
function, never for a numbered implementation step.

| Responsibility | Placement |
| --- | --- |
| Binding envelope, bounded store, snapshots, intent references, endpoint candidates | `internal/pkg/learnedrules/` |
| Generic control codecs, capability negotiation, authenticated subscriptions | `internal/pkg/learnedrules/wire/` |
| Projection from logical bindings onto backend owner capabilities | `internal/pkg/learnedrules/admissionadapter/` |
| SIP interpretation, VoIP context, media qualification, call/dialog resolution | `internal/pkg/voip/learnedrules/` and existing `callselection` tracker |
| Existing media API and signed proof compatibility | `internal/pkg/mediarules/`, especially its wire facade |
| Source setup, packet integration, and output coordination | Existing hunter, processor, pipeline, and tap packages |

The shared core must not import `sip`, `voip`, `callselection`, `callregistry`, LI
implementation packages, or generated call-shaped protobuf types. Wire and VoIP
compatibility adapters may translate those types. Avoid a second authoritative
store beside the new engine: legacy views and the generic service publish from
the same committed binding state.

Keep the proven `mediaadmission.Controller` and its backend integration. Generalize
its diagnostic owner label while preserving minted session/generation tokens,
shared endpoint references, pending reservations, uncertainty handling, and
complete-snapshot recovery. Its package can remain for compatibility; the shared
binding store does not depend on its call-shaped API.

### Binding contract

A logical binding has the following validated, owned fields:

| Field | Contract |
| --- | --- |
| ID and binding revision | Stable relationship identity and immutable definition version. |
| Authority ID and epoch | The authenticated issuing processor and its current control generation. |
| Adapter ID and context version | A registered interpretation with an explicitly supported contract. |
| Subject ID and incarnation | A bounded opaque identity for one subject lifetime; interpreted by the adapter. |
| Attribution context | Adapter-defined namespace within which ambiguity is evaluated. |
| Intent references and revisions | The configured selections or protected grants that justify this binding. |
| Scopes | Explicit eligible sources and their mapped observation domains; interfaces remain part of source mapping. |
| Selectors and qualifiers | Exact typed match requirements. |
| Evidence references and adapter context | Owned, bounded, versioned data validated by the registered adapter codec. |
| Not-before and expiry | Finite authority interval with the existing clock-uncertainty protections. |

Keep publication/snapshot revision separate from immutable binding revision.
Publishing a snapshot must not rewrite a signed artifact's revision. Subject
incarnation is separate from authority epoch: identifier reuse within the same
processor runtime cannot inherit the old relationship.

Use an immutable adapter registry constructed at startup. Its typed interfaces
validate context, authorize publication/renewal against current intent, qualify
candidates, and validate attribution. The store owns lifecycle enforcement;
adapters own protocol meaning. Context can be opaque to the store only after a
registered codec validates its type, version, canonical form, and bounded size.
There is no arbitrary executable rule language or unrestricted context map.

### Matching, candidates, and shared ownership

The initial selector is an exact transport endpoint: normalized IPv4/IPv6 address,
explicit UDP or TCP protocol, nonzero port, and source/destination/either
direction. Fields within a selector are conjunctive; selectors are alternatives.
Every required qualifier applies to its selector branch. VoIP emits UDP/either
endpoints with versioned RTP, RTCP, or multiplexed-media qualification.

Matching returns bounded candidate references and an explicit overflow result.
It never labels a truncated candidate set unique. The adapter resolves ownership
within its attribution context; two adapters can independently associate the
same packet with different subjects. VoIP retains its current endpoint ownership
intersection and ambiguity rejection rather than adopting a generic first-hit
resolver.

Logical binding identity and physical admission identity remain distinct. Group
projection ownership by authority epoch, adapter, subject incarnation, and local
domain, with binding references accounting for all retained intent. Shared
physical entries survive withdrawal of one relationship while another still
needs them. Backend token equality must never substitute for subject authority.

Existing kernel endpoint maps are candidate admission, not exact generic
transport/direction matchers. Userspace enforces complete semantics. A source
advertises a capability only when its entire path, including static BPF and
required qualifiers, can implement it. Unsupported or incomplete installation
is visible and does not become broad capture permission.

### Wire and evidence compatibility

Introduce `api/proto/learned_rules.proto` with a separate versioned learned-rule
service. Requests and readiness responses identify adapter/context versions,
selector and qualifier versions, and accepted packet-evidence formats. Preserve
the existing `MediaControlService` and its ordinary v1/grant-bearing v2 contracts
as compatibility views over the shared engine.

Define shared evidence messages in `api/proto/learned_evidence.proto`, generated
into the independent `api/gen/learnedevidence` package. This message-only schema
imports neither data nor management/control schemas. Both packet and control
schemas can import it without a generated Go package cycle; legacy signed media
artifacts are byte fields, not imports of call-shaped management messages.

Prefer the new service when both peers support the complete required contract.
Use the legacy service only for a VoIP binding that the compatibility adapter can
represent exactly, and only after an explicit unsupported-service/capability
result. Authentication, signature, scope, installation, and malformed-message
errors must not trigger fallback. Existing grant-required deployments must never
fall back to ordinary v1 or distribute private selectors.

`CapturedPacket.capture_selection_proof` field **16** is already an untagged
serialized `MediaRule`. Keep its encoding and historical decoder intact. Add an
explicitly versioned `learned_capture_evidence` field at the next free field
number, currently **17**, and mirror it in `pipeline.PacketEnvelope`. Its envelope
contains bounded candidate references with a typed proof variant per candidate,
including ordinary binding references and exact legacy signed-media bytes. This
allows diagnostic and protected VoIP candidates to coexist in one packet.
Unknown kinds and contradictory simultaneous legacy/new fields are rejected;
emit either field 16 or field 17 per packet. Legacy field 16 cannot represent
mixed adapter evidence and must not silently discard those associations.

Negotiate evidence support separately from control-service support. Raw protobuf
peers may silently discard unknown fields, so a producer must establish that its
receiver and any relay path preserve and validate the chosen format before
forwarding evidence-dependent packets. New ordinary evidence needs authenticated
source scope and authoritative binding validation before subject attribution.
Missing retained binding state is unresolved, not evidence for a new lifetime.

For protected VoIP, initially retain the exact existing signed `MediaRule` as the
proof artifact, including when carried through the new control/evidence contract.
The VoIP adapter must verify its complete semantic equivalence to the binding:
authority, incarnation, revisions, intent references, scopes, validity, endpoints,
and media qualification. No new generic signing scheme or grant purpose is
needed for this extraction. A future protected adapter must introduce an explicit
authorization contract for its selector semantics.

For historical protected ingress, derive the captured VoIP binding from the exact
legacy proof or compare against its immutable captured context. Do not require
that binding or its issuing epoch to remain active in the current learned-rule
store. Capture-time authenticity and current LI delivery authorization remain
separate checks. Ordinary reference-only evidence with no retained authoritative
state cannot use this signed-proof recovery path.

### Configuration and operator behavior

Existing `*.voip.media_rules`, signaling/media policies, interface-domain maps,
resource limits, and root-level LI settings continue to work. Translate them to
typed engine and VoIP-adapter settings internally. Detect conflicting settings
if an existing entry point supplies incompatible values. Retain the existing
`pending_dialog_capacity` configuration spelling while generalizing the internal
owner label and accounting.

Generic runtime construction takes typed adapter registrations and settings;
production VoIP registers its adapter through the existing commands. Tests inject
the diagnostic adapter into that same factory on generic hunt and local tap
paths, without setting VoIP mode. The test adapter is compiled only in tests and
does not add a public administration endpoint or speculative CLI rule syntax.

Preserve existing media status fields as a VoIP view. Add generic status for
adapter capabilities, desired/effective revisions, installation failures,
candidate overflow, and lifecycle/resource outcomes, using bounded labels.

## Implementation sequence

Complete each step's verification before checking it off. Keep dependent changes
sequential; core, wire, and adapter work may be developed independently only after
their contracts agree. Format changed files before staging, and commit verified
implementation and plan updates together.

### 1. Establish contracts and compatibility fixtures

- [x] Define the shared Go binding, subject, intent, selector, qualifier, candidate,
      application-report, and adapter-registry interfaces above. Document ownership,
      canonicalization, bounds, and callback/locking requirements with the types.
- [x] Define the generic wire/evidence schema, readiness negotiation, error classes,
      and legacy representability checks before migrating producers.
- [x] Add focused dependency checks showing that the shared core does not import
      protocol or LI implementations. Check both ordinary and LI build partitions.
- [x] Capture small independent legacy v1/v2 wire/proof vectors and historical
      evidence fixtures. Generate test packets, certificates, and protected stores
      in tests; do not reference missing or private PCAP files.
- [x] Preserve regression coverage for expiry, snapshot atomicity, shared endpoint
      ownership, media ambiguity, signature mutation, and original proof replay.

Verification: the new contracts and fixtures compile without changing live VoIP
behavior. Tests validate actual wire bytes and authorization boundaries rather
than mirroring a conversion helper's own output.

### 2. Extract the lifecycle store and owner projection

- [x] Move common store/session, revision, snapshot, renewal, withdrawal, expiry,
      cloning, resource accounting, and observer behavior from `mediarules` into
      `learnedrules`. Preserve conservative activation/expiry, reconnect tokens,
      stale callback rejection, and immutable published state.
- [x] Move call-specific validation, `Resolve`, and `ResolveDialog` out of the
      shared store into the VoIP adapter. Validate adapter context before committing
      any binding, including complete replacement snapshots.
- [x] Implement transport/direction-aware endpoint candidate lookup, registered
      qualifier dispatch, bounded candidate reporting, and explicit overflow.
- [x] Generalize `mediaadmission.OwnerID`'s diagnostic Call-ID label and its
      constructor arguments to an opaque owner label. Preserve real authority in
      minted tokens and keep current configuration decoding compatible.
- [x] Extract shared admission projection using generic subject/incarnation keys.
      Preserve endpoint reference ownership, reservation bounds, retries, uncertain
      backend effects, and complete desired-state reconciliation.
- [x] Provide `mediarules` compatibility facades over the new engine. Ensure no
      independent legacy registry can diverge from generic committed state.

Verification: retain or migrate `TestSnapshotsAreAtomicAndOwned`,
`TestMonotonicExpiryAndReconnectDoNotExtendRules`,
`TestProjectionUsesLocalOwnersAndPreservesSharedEndpoints`, and the controller's
shared-ownership, lost-observation, and pending-owner lifetime regressions. Add
multiple-adapter/context and candidate-overflow cases, including zero-match,
ambiguous, shared-selector withdrawal, and subject-ID reuse.

### 3. Introduce the generic control service

- [x] Implement the control and independent evidence schemas and codecs, adding
      them to `api/proto/Makefile` and regenerating checked-in Go outputs with
      compatible stable tooling. Check generated package dependencies. Do not
      hand-edit generated files or upgrade unrelated dependencies.
- [x] Reuse bounded snapshot staging, ordered deltas, subscriber limits, and
      application-report ownership from `mediarules/wire`. Require verified peer
      identity, current source registration, explicit scope, and compatible adapters.
- [x] Keep immutable binding revisions independent of stream revisions and retain
      all-or-nothing installation of a complete validated snapshot.
- [x] Report applied revision, complete synchronization, capability refusal, and
      installation failure. Candidate backend readiness alone is insufficient.
- [x] Implement the existing media service as an exact VoIP projection. Preserve
      ordinary v1 and grant-bearing v2 behavior and old-peer status reporting.
- [x] Implement explicit new-to-legacy negotiation and its refusal paths. Test that
      authorization failures and incompatible generic semantics cannot downgrade.

Verification: exercise old client/new server, new client/old server, and new/new
combinations with ordinary and protected VoIP. Cover incomplete snapshots,
oversized input, wrong issuer, changed epoch, unknown adapter/qualifier/version,
stale reports, old stream callbacks, and capability removal on reconnect.

### 4. Move VoIP behavior onto the shared runtime

- [x] Refactor `processor/media_control.go` so the existing SIP tracker and matcher
      propose typed VoIP bindings while shared services handle publication,
      lifecycle, placement, and installation reports.
- [x] Implement the VoIP adapter's canonical context conversion, RTP/RTCP
      qualifiers, endpoint ownership intersection, exact proof selection, and
      signaling/dialog resolution. Preserve call incarnation and selection revision.
- [x] Separate generic runtime setup in `hunter/media_rules.go` from VoIP adapter
      registration. Move UDP-only parsing and media heuristics into the adapter;
      generic endpoint matching supports both UDP and TCP.
- [x] Refactor `cmd/tap/media_rules.go` to use the same engine, adapter, and matcher
      through an in-process subscription. Keep the actual `<tap-id>-local` source
      identity and interface-domain mapping.
- [x] Retain existing signaling/media policy choices, exact source scope, SDP
      updates, BYE/CANCEL validation, trailing grace, timeout, and ambiguous media
      behavior. Historical SIP and returned media cannot bootstrap new authority.
- [x] Preserve ordinary filter selection independently of learned bindings. Only
      validated VoIP attribution may populate inherited call filter IDs.

Verification: run the existing hunter/tap resolver tests and processor media-control
tests, including untrusted/historical input, cross-source learning, SDP updates,
endpoint/domain mismatch, dialog validation, withdrawal, and media capture on a
source that never saw INVITE. Exercise local and distributed operation through
the same adapter code.

### 5. Carry generic evidence through the packet path

- [x] Implement the new typed field in raw protobuf conversion and
      `pipeline.PacketEnvelope`, with owned immutable copies and bounded candidate,
      context, and per-candidate proof lengths. Preserve direct filter evidence
      separately and support mixed adapter candidates in one envelope.
- [x] Negotiate evidence acceptance at the raw receiver/readiness boundary and
      propagate preservation requirements through relays. Reject unsupported paths
      before accepting evidence-dependent delivery rather than losing unknown fields.
- [x] Enforce one selected evidence representation per packet. Preserve field 16
      for legacy senders and historical records; reject contradictory dual forms.
- [x] Extend producer admission and batch-sealing validation to new evidence,
      including ordinary shared-owner packets carrying protected proof. Keep
      process-local current-selection callbacks off the wire.
- [x] Preserve exact proof bytes, actual source/interface/domain, and capture time
      through batching, queues, spool/custody, relays, and restart replay.
- [x] Validate live and ordinary reference-only candidates against authoritative
      binding/intent state before subject-dependent attribution and output. Missing
      or expired state cannot create an owner. Protected historical evidence follows
      its original signed-proof validation path without requiring current learned
      state; independently selected ordinary traffic retains its policy. A valid
      candidate from another adapter must not preserve unvalidated inherited VoIP
      filter IDs from an unresolved candidate in the same packet.
- [x] Keep historical validation separate from current learning and ensure replay
      cannot renew a binding, recreate a subject incarnation, or confer current capture.

Verification: extend protobuf ownership and producer provenance tests. Include
candidate tampering, unknown evidence version, unsupported relay/receiver,
contradictory fields, capture-time mismatch, mutation between admission and sealing,
retained backlog, expired/finalized subjects, and legacy historical replay.

### 6. Preserve the complete LI path

- [x] Keep the existing policy owner's signing and verification of exact legacy
      media-rule artifacts. Validate complete generic-binding/proof equivalence at
      publication, source use, and central protected ingress. Historical comparison
      uses captured immutable context or reconstruction from proof, not the current
      binding registry or current control epoch.
- [x] Preserve media-only grant scope and purpose. Generic TCP endpoints, unknown
      adapter context, and future selector types cannot acquire media-grant authority.
- [x] Keep opaque public intent references bound to private task identity,
      activation generation, administrative incarnation, and current definition.
      Task changes or revocation invalidate stale eligibility.
- [x] Retain current capture-policy revision checks, original capture-time checks,
      offline expiry, clock uncertainty, source exclusion, and proof validation at
      both producer boundaries regardless of the global provenance-mode setting.
- [x] Preserve current delivery eligibility, finalized-call/media-age checks, and
      byte-exact replay. Capture-source metadata and delivery sequence context remain
      governed by their existing interfaces.

Verification: retain `filterpolicy/selection_test.go`, `capturegrant/proof_test.go`,
`hunter/reliable_media_grants_integration_test.go`, and
`processor/central_task_capture_integration_test.go`. Extend them to exercise
generic control/evidence plus the legacy compatibility route. Include task
reactivation, source change, expiry, withdrawal, restart, conflicting binding/proof
contents, and deliberate attempts to broaden a media grant. Replay a signed legacy
artifact after its learned binding and control epoch are gone, proving that current
delivery authorization still governs eligibility without a live-store dependency.
Include actual durable spool/custody and restart replay, checking that the original
signed bytes, source identity, domain, and capture timestamp survive unchanged.

### 7. Prove another adapter through production paths

- [x] Implement a test-only diagnostic adapter with its own typed context, intent,
      subject ID/incarnation, and attribution context. It has no Call-ID, SIP fields,
      call-registry object, or LI task.
- [x] Drive it through actual processor publication, authenticated generic control,
      effective hunter installation, UDP/TCP matching, packet forwarding/evidence,
      and an ordinary observable output. Use the production runtime factory.
- [x] Repeat matching and output through an in-process local tap subscription with
      VoIP mode disabled. Do not use a separate test implementation of the engine.
- [x] Exercise directional matching, IPv4/IPv6, explicit scope, replacement, expiry,
      reconnect, shared physical entries, subject reuse, candidate overflow, and
      capability rejection. Verify the preceding capture filter admits candidates.
- [x] Demonstrate concurrent diagnostic and VoIP associations without merging their
      subjects, inheriting each other's intent, or treating cross-adapter overlap as
      VoIP ownership ambiguity. Exercise both a remote hunter and the actual local
      tap construction path; a separately instantiated matcher is insufficient.

Verification: tests construct their own packets, TLS identities, clocks, and stores.
Use deterministic lifecycle assertions and fault injection; no new protocol tracker
or runtime diagnostic CLI is required to prove the extension boundary.

### 8. Update operator documentation and finish verification

- [x] Update `docs/DISTRIBUTED_MEDIA.md`, applicable hunt/process/tap READMEs, and
      the manual's distributed selection, LI, and configuration sections. Describe
      the shared engine and the production VoIP adapter accurately; identify future
      adapters and selectors as unsupported until implemented.
- [x] Document control/evidence negotiation, upgrade order, legacy compatibility,
      selector capabilities, installation status, overflow, and historical behavior.
      Keep existing configuration examples valid and do not require a new rule DSL.
- [x] Update every affected manual translation listed in
      `docs/manual/languages.json`, including changed fuzzy entries, then run
      `make manual-check` and `make manual`.
- [x] Run the relevant package race suites and established repository gates below.
      Record actual results and limitations before marking this plan complete.
- [ ] Format changed files and generated outputs appropriately, inspect the final
      diff, then commit implementation, documentation, and verified plan status.

## Verification commands and evidence

Use focused package runs while developing. After integration, run the common
engine, compatibility, producer, pipeline, and VoIP suites under both ordinary and
LI builds, including the new packages:

```bash
go test -race -tags all ./internal/pkg/learnedrules/... ./internal/pkg/mediarules/... \
  ./internal/pkg/mediaadmission/... ./internal/pkg/voip/... ./internal/pkg/hunter/... \
  ./internal/pkg/pipeline/... ./internal/pkg/processor/... ./cmd/hunt ./cmd/process ./cmd/tap

go test -race -tags 'all li' ./internal/pkg/learnedrules/... ./internal/pkg/mediarules/... \
  ./internal/pkg/mediaadmission/... ./internal/pkg/voip/... ./internal/pkg/hunter/... \
  ./internal/pkg/pipeline/... ./internal/pkg/processor/... ./internal/pkg/filterpolicy/... \
  ./internal/pkg/capturegrant/... ./internal/pkg/li/... ./cmd/hunt ./cmd/process ./cmd/tap

make test
make vet
make build-matrix
make verify-no-li
make test-ebpf
make manual-check
make manual
```

The eBPF gate is relevant because ownership projection/controller integration
changes; run its actual isolated kernel and command tests. CUDA linkage remains
covered on the project's configured CUDA builders through the established build
matrix option. Use existing test infrastructure and clean task-owned temporary
caches after verification.

Performance measurements may describe propagation and capacity, but this plan
adds no latency, throughput, CPU, RSS, or outage-duration acceptance target.
Existing configured resource enforcement, cryptographic bounds, authorization,
expiry, and durability checks remain correctness requirements.

Completion evidence must show current VoIP behavior on the common engine, the
independent adapter on real remote/local paths, mixed-version compatibility,
protected VoIP authority and replay, and ordinary outputs without LI. Passing
core unit tests alone does not complete the packet and authorization integration.

## Verification record

The engine, compatibility services, actual generic remote/local packet paths,
mixed VoIP/diagnostic tap path, and protected local capture-to-X3 path pass focused
race tests in ordinary and LI builds. Diagnostic capture includes UDP/IPv4 and
TCP/IPv6 without SIP or LI identity. Frozen v1/v2 fixtures preserve historical
field-16 evidence; typed encrypted spool/custody tests preserve original signed
bytes, source/interface/domain/time, and policy across restart after binding
removal and an authority-epoch change. Central task-to-MDF tests cover both
evidence formats and deduplication modes.

The single bounded closure review identified and repaired source-domain isolation
in central typed attribution and application-decoder truncation flags incorrectly
vetoing complete endpoint packets. Regressions cover overlapping source-local
domains mapped to separate central realms, ambiguity between eligible owners,
complete port-5060 UDP payloads, actual IPv4/IPv6 UDP/TCP truncation, and fragments.
Required-gate fixture failures were corrected without weakening their assertions.

All required checks pass on the final implementation:

| Check | Result |
| --- | --- |
| Complete affected package race suites, `all` and `all li` | Pass |
| `make GOFLAGS=-p=1 test` | Pass, including the full integration package and LI packages |
| `make vet` | Pass |
| `make build-matrix` | Pass for all supported ordinary/LI partitions |
| `make GOFLAGS=-p=2 build-matrix-cuda` | Pass, including CUDA link builds, GPU package tests, and vet |
| `make verify-no-li` | Pass |
| `make test-ebpf` | Pass: actual isolated kernel, socket, tap, and hunter command tests |
| `make manual-check` and `make manual` | Pass: all three editions, 5859/5859 current messages translated in both Catalan and German |

CUDA tests use the existing project kernel library and `/opt/cuda/lib64` in
`LD_LIBRARY_PATH`. Compiler/package concurrency settings keep the shared test
machine within its temporary-storage quota and avoid fixed-port contention.
`GOFLAGS` is passed as a Make command-line variable for the standard test target;
exporting it through the environment causes the existing Makefile to replace it
with `-trimpath`, which is incompatible with source-path-based X1 test helpers.
These execution settings do not change the tests or product behavior.

The bounded closure campaign completed one discovery round, one primary repair
batch, one integrated review, and one supplemental repair batch. All three
findings are fixed and verified; no blocking requirement or external check remains.
