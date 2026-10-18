# Central task selection and capture-source export

**Date:** 2026-10-18

**Status:** Complete. Implementation, tests, documentation and translations are
committed in `8fd1b345`. Required checks and the bounded closure review pass.

**Baseline:** `main` at `757719f5`, including the distributed-media implementation
in `bb991f88` and its completion record. This plan completes the remaining LI
integration identified by the
[verification and second opinion](/home/grischa/2026-10-18-satellite-distributed-poi-verification-757719f5.md).
It builds on the existing
[distributed media plan](distributed-media-admission-and-call-continuity.md).

## Outcome

A processor or tap can keep task target patterns local, select a call centrally,
and authorize hunters to capture its media through temporary rules. Hunters
receive scoped capture permission and the necessary media endpoints. Target
patterns stay on the processor/tap.

Delivered signalling and media identify the hunter, interface and observation
domain that captured each packet, alongside its capture timestamp. Changing the
capture source preserves the processor's delivery identity, call association and
existing sequencing behavior. A receiver can observe that change directly.

These are general lippycat features: filter distribution policy, signed capture
grants and exported capture-source metadata. Shared packages use those concepts;
the existing LI task and delivery adapters provide their actual LI integration.

| Deliverable | Observable result |
| --- | --- |
| Central task filters | Task provisioning, modification and recovery retain local-only filters without sending their patterns to hunters |
| Grants for remote selection | A signed, scoped grant plus a current media rule permits selected RTP/RTCP without a target-bearing hunter filter |
| Purpose-aware admission | A media grant cannot become permission for SIP, arbitrary UDP or unrelated local matching |
| Capture-source export | The receiver decodes source node, interface, domain presence/value and original capture time from each enabled product |
| Durable source metadata | Reordering, fan-out, queueing and journal replay preserve the encoded source information |
| End-to-end evidence | Task provisioning through delivery demonstrates central selection, source changes, withdrawal and disconnected expiry |

## What needs connecting

At the assessed baseline, the local-only filter scope, call tracker,
media-control service, endpoint admission, protected reliable forwarding and
duplicate detector provide the underlying functionality. Two boundaries need
completion.

At that revision, task-generated filters default to distributed scope. Signed
capture-policy snapshots contain full matching filters, reject local-only
entries, and derive hunter membership from those distributed filters. Changing a
task filter's scope alone therefore removes the current basis for capture
authorization.

At that revision, the output encoders use the configured processor identity for
delivery continuity. They preserve capture timestamps but do not export the
separate hunter/interface/domain fields. The journal's lifecycle provenance is a
closed authorization union: non-call RTP records include some source fields,
while call-associated records and normal signalling records do not provide
equivalent source metadata.

| Boundary | Existing integration points |
| --- | --- |
| Task filters and ownership | `internal/pkg/li/filters.go`, `manager.go`, task activation/modification/recovery paths |
| Signed task capture authority | `internal/pkg/li/handover_authority.go`, `processor/processor_li_handover.go` |
| Generic policy format and persistence | `api/proto/management.proto`, `internal/pkg/filterpolicy/`, `processor/processor_shared_policy.go` |
| Hunter capture membership | `hunter/filtering/capture_policy.go`, `hunter/observation_domain.go`, `hunter/forwarding/manager.go` |
| Media-rule association | `api/proto/media.proto`, `mediarules/`, `mediarules/wire/`, `processor/media_control.go`, `hunter/media_rules.go`, `cmd/tap/media_rules.go` |
| Capture and replay validation | `processor/processor_li_handover.go`, `hunter/reliable_packets.go`, packet forwarding, spool and receipt adapters |
| Source fields | `types.PacketDisplay`, `pipeline.SourceProvenance`, processor packet conversion and deferred call correlation |
| LI output | `li/x2x3/{pdu,attributes,x2_encoder,x3_encoder,deferred_sequence}.go`, RADIUS encoder, `processor_li_ordering.go` |
| Durable delivery | `li/delivery/client_journal.go`, journal record/replay codecs, `processor_li_persistent.go` |

## Implementation contracts

### 1. Task distribution is explicit

Add a processor/tap LI setting using the existing distribution-scope values:
`li.task_filter_distribution_scope: distributed|local_only`. Keep `distributed`
as the compatibility default. The setting applies to task-created identity
filters, derived filters and reconstruction after restart.

In `local_only` mode, the LI manager retains the complete filters and their task
ownership on the processor/tap. Central matching uses the real task-derived
filters. Administrative queries retain their existing authorized visibility;
hunter queries, subscriptions and policy exports omit private selector contents.
Validate unsupported task/source combinations visibly at configuration or task
activation time, rather than silently distributing a local-only filter.

### 2. Capture grants are separate from matching filters

Extend the signed policy contract with a typed, generic capture-selection grant.
A grant is permission to use an authorized selection path; it is not a matcher or
a kernel IP selector. Keep a separate grant index instead of adding grant IDs to
unrestricted filter membership.

| Grant fact | Required meaning |
| --- | --- |
| Opaque selection reference | Names centrally owned selection authority without exposing its target pattern |
| Generation/revision | Changes when the selected definition or activation changes; stale references cannot inherit new authority |
| Purpose | Explicitly permits processor-selected RTP/RTCP; other packet classes require their own permission |
| Issuer | Binds use to the configured authenticated processor controlling the media rule |
| Source scope | Bounds eligible hunters and observation domains |
| Validity/offline policy | Finite signed interval and existing disconnected-capture permission |

The LI adapter privately binds the public reference to the current task,
activation generation, exact selector definition and source authority. Keep that
binding recoverable under the existing protected state contract. An existing ID
may be reused only if it is opaque and cannot disclose target information.
Pattern descriptions, structured target criteria and public unkeyed hashes of
guessable target patterns must not appear in the exported grant or opaque
authority payload. Rotate or invalidate references when their binding changes.

The matching-filter list can be empty while valid grants exist. Empty matching
filters plus empty grants means withdrawal, not broad capture permission. Mixed
distributed-filter and grant-based deployments must retain distinct evidence for
each path.

Grant-bearing signed snapshots need an explicit new protocol version. New peers
retain the existing version for ordinary deployments and historical verification;
older peers reject the new contract. Extend media-rule/provenance versions and
capability reporting where the new references change their meaning. Explicitly
requested grant-based operation must fail visibly on unsupported peers. An
upgrade must never fall back to sending private patterns.

### 3. Admission requires the grant and the exact rule

Before admitting new media, validate the installed signed grant and the current
authenticated media rule together: issuer/control session, source/domain,
selection reference/revision, exact call incarnation, unambiguous endpoints,
RTP/RTCP kind and both validity intervals. Cap rule validity by its grant and
current task authority. Kernel endpoint matches remain candidates for userspace
validation.

Carry typed selection evidence through immediate UDP handling, asynchronous TCP
paths where applicable, buffered release, reliable batch sealing and processor
validation. A bare wire-supplied grant ID is not proof. Recheck at the existing
producer boundary so withdrawal or policy replacement cannot retag an old packet
under new permission.

A media-only grant must not authorize `ResolveSignalling`, direct IP matching or
all-SIP forwarding. Existing selected-dialog forwarding continues under its
applicable signalling authority. If an association needs signalling permission,
represent that purpose explicitly and keep the existing exact dialog checks.
The current rejection of `signalling-policy all` in LI-owned capture remains.
Initial central selection needs signalling from a source already authorized to
observe it, such as the tap's local capture path.

Historical authorization and current capture remain separate. Previously accepted
packets retain their original signed policy, source, capture time and selection
proof. Historical validation checks authority at capture time; expiry of that
capture lease alone must not discard an otherwise eligible retained packet.
Current delivery still checks task generation, revocation, cutoff, destination
and call admission. Replay never creates or renews current capture rules.

### 4. Export source metadata in the encoded product

Use one immutable capture-source value built from trusted normalized provenance:
source node, interface/source name, and observation-domain presence plus value.
Keep known domain zero distinct from unknown. Obtain capture time from the
existing timestamp path and preserve its documented missing-time behavior.
Observation domain remains distinct from the delivery protocol's domain field.

Encode a namespaced, versioned lippycat capture-source value inside the existing
`x2x3.AttrProprietary` container. Define its namespace/signature, source subtype,
version, field order and length bounds before writing the encoder. Use existing
source-string bounds and the containing record/message limits; validate UTF-8,
checked aggregate sizes, domain flags and complete consumption. Provide the
matching receiver decoder in the same package. This is a documented private
extension using an existing container, with no new standard identifier implied.

Add `li.delivery.capture_source_metadata`, defaulting to `false` for wire
compatibility. When enabled, all configured destinations must be intended to
consume the extension. Validate required source metadata before consuming an
output sequence or admitting a product. Unknown legacy source fields stay
explicitly unavailable; never substitute the processor ID as the capture hunter.

Build the attribute once before deferred delivery and destination fan-out. Source
changes do not enter the sequence-context key. Every destination receives the
same source bytes and sequence for a product. Integrate signalling, call-backed
and non-call media, and the existing RADIUS source adapter.

Journal the exact encoded product through the current delivery path. Embedded
source metadata then survives persistence/replay without changing the lifecycle
authorization union. Supply inspection/receiver helpers that read the source
attribute from both live and journaled product. Already encoded legacy records
replay with their original bytes and report source metadata unavailable when
absent. New metadata must not be synthesized into those records during recovery.

### 5. Validate operation and measure the actual boundaries

Use plain-IP synthetic traffic and invented target identities. Exercise a tap
with remote hunters as well as a separate processor receiving authorized SIP.
Verify that the receiver observes a capture-source change while the call and
delivery context continue.

Measure signalling observation, central selection, rule activation and first
admitted media separately. The initial gap includes transport, processing and
installation; a fixed one-round-trip promise is insufficient. Record missing
early media and expiry during link loss without inventing pass/fail latency or
packet-loss thresholds.

The deduplication window bounds packet age and retained comparison evidence, not
the overall duration of an overlap. Include an overlap longer than the window
whose corresponding copies arrive promptly, and separately test delayed copies
and replay beyond the window. Report existing counters and retain conservative
handling of unsupported or ambiguous traffic.

## Work sequence

Complete the contract work first. Task/grant publication and source export can
then proceed independently, while capture admission depends on the grant
contract. The integrated demonstration requires both paths, followed by the
documentation and verification work. Existing failover and reliable transport
are prerequisites already present in the baseline.

### 1. Define the grant and source-export contracts

- [x] Read applicable repository instructions and confirm these integration points
      at the implementation revision; preserve concurrent changes.
- [x] Specify the generic grant, private task/selector binding, purpose checks,
      source/domain scope, validity and replay representation with bounded fields.
- [x] Specify signed policy/media/provenance protocol versions, capability checks,
      legacy readers and explicit unsupported-peer behavior.
- [x] Define the private source-attribute namespace, versioned codec, absence
      semantics, length limits and receiver parser using `AttrProprietary`.
- [x] Add typed processor/tap configuration for task-filter distribution and
      source export through existing CLI/Viper conventions and build-tag adapters.

**Evidence:** contracts distinguish matching, capture permission, source facts
and delivery authorization without depending on target-bearing hunter filters.

### 2. Connect central task filters to signed grants

- [x] Apply task distribution scope during create, modify, derived-filter update,
      deactivation and restart/recovery; preserve task/filter ownership and the
      existing transactional persistence/reconciliation behavior.
- [x] Publish public grants for central-only selections while keeping complete
      selectors and exact binding state in the protected processor/tap owner.
- [x] Retain existing distributed policy behavior and local central matching;
      cover mixed local-only/distributed task selection.
- [x] Remove private selector content from every hunter-facing filter, snapshot,
      subscription, rule and authority export. Include descriptions, structured
      criteria, derived selectors and guessable selector digests in the check.
- [x] Cover activation/definition changes, suspension, expiry, deactivation,
      reactivation with reused IDs, source exclusion and task-owner incarnation
      changes. A failed update must not leave old authority usable as new policy.

**Evidence:** provision and modify an actual task through the existing X1 API;
central matching works, and captured hunter-bound messages/storage contain no
target patterns. Authorized administrative visibility still works.

### 3. Enforce grants through capture and reliable forwarding

- [x] Install a separate bounded grant index in the hunter policy owner and carry
      grant references in the media association and typed packet evidence.
- [x] Validate grant/rule intersection in the hunter and in-process tap resolver,
      including exact endpoint ownership, purpose, issuer, scope and expiry.
- [x] Extend producer membership/revalidation for grant evidence through immediate,
      buffered and asynchronous release. Preserve independent direct/inherited
      matching evidence and signed policy revision boundaries.
- [x] Validate original capture evidence at raw ingress and delivery; retain
      current task authorization and receipt/spool behavior for historical replay.
- [x] Verify independent expiry, withdrawal, renewal ordering, disconnect/offline
      policy, clock rollback, incomplete snapshots and failed kernel updates.
- [x] Add negative tests for absent/wrong grant, stale revision/session, changed
      selector, wrong source/domain, ambiguous endpoints, SIP under a media-only
      grant, unrelated UDP, grant-ID spoofing and unsupported older peers.

**Evidence:** a hunter with no target filters captures only currently authorized
rule-selected media, and neither stale local buffers nor replay can re-arm it.

### 4. Encode, deliver and recover capture-source metadata

- [x] Assemble the immutable source value once from trusted local/remote packet
      provenance; preserve source/time through deferred call correlation.
- [x] Implement bounded encoding and receiver parsing, including legacy absence,
      unrelated proprietary attributes, duplicate recognized values, unsupported
      versions, malformed lengths, invalid flags/UTF-8 and oversized inputs.
- [x] Integrate SIP X2, RTP X3 and RADIUS encoders with the explicit output setting;
      validate before sequence allocation and preserve existing timestamp fields.
- [x] Verify source changes preserve processor delivery identity and sequence
      continuity through RTP reordering and identical destination fan-out.
- [x] Exercise ordinary queues, persistent signalling/media, call and non-call
      records, restart/recovery and journal inspection. Decode actual product at
      the receiver and compare original source bytes after replay.
- [x] Keep legacy product fixtures valid and distinguish absent provenance from
      known domain zero. Preserve task/call closure, expiry and revocation checks.

**Evidence:** receiver-decoded output identifies the capturing hunter/interface/
domain before and after a path change, including delivery after restart.

### 5. Demonstrate task-driven operation across capture sources

- [x] Build deterministic generated fixtures in test-owned temporary directories;
      include UDP/TCP signalling, early media and RTP/RTCP with stable endpoints.
- [x] Run a tap-local task selection with remote hunters receiving grants/rules
      only. Assert absence of target patterns at both hunters.
- [x] Capture media first at A and then at B, where B never saw INVITE, with no
      endpoint change or new SIP negotiation. Verify call ownership and decoded
      receiver-visible source changes with duplicate suppression off and on.
- [x] Exercise authorized associated BYE/UPDATE under the applicable signalling
      policy and verify central validation, trailing grace and rule retirement.
- [x] Test a late subscriber, control-link loss, independently expiring rules and
      capture policy, buffered release, reconnect, retained backlog and restart.
- [x] Record observation/selection/activation/first-media times and raw, admitted,
      retained, suppressed and delivered counts. Separate delayed-copy coverage
      from total overlap duration and downstream delivery retries.
- [x] Exercise live eBPF rule changes using the existing isolated container gate,
      plus the correct userspace path with kernel admission disabled.

**Evidence:** one complete task-provisioning-to-receiver trace demonstrates both
target-pattern privacy and capture-source continuity under the actual LI checks.

### 6. Document, verify and record completion

- [x] Update `docs/DISTRIBUTED_MEDIA.md`, LI integration/recovery documentation and
      affected processor/tap/hunter command references, including defaults,
      configuration migration, grant purposes and private receiver compatibility.
- [x] Update affected manual sources and every configured translation; run
      `make manual-check` and `make manual`.
- [x] Run focused ordinary/LI race suites for policy, grants, capture release,
      media rules, LI task authority, encoding and journal replay.
- [x] Run `make test`, `make vet`, `make build-matrix` and `make test-ebpf` with the
      required test permissions. Record executed gates and actual limitations.
- [x] Verify this plan's outcomes against production paths and receiver results;
      check off only demonstrated tasks and correct the preceding plan's closure
      note when these integration gaps are actually resolved.
- [x] Format changed files and commit the implementation, documentation,
      translations and updated plan together.

## Completion criteria

Completion requires all of the following observed behaviors:

- [x] An API-provisioned task selects calls centrally without exporting its target
      patterns or guessable pattern fingerprints to hunters.
- [x] Current scoped grants and exact media rules authorize capture together;
      purpose, source, revision, expiry and withdrawal failures reject capture.
- [x] A media grant cannot independently authorize signalling or broaden direct
      matching; existing LI-owned capture restrictions remain effective.
- [x] Accepted historical packets retain their original authority and source,
      pass current delivery checks, and never renew current rule authority.
- [x] A receiver can decode the actual capture source from enabled signalling and
      media products while processor delivery identity and call continuity hold.
- [x] Encoded provenance survives ordinary delivery, reordering, fan-out and
      persistent recovery; legacy bytes retain their original meaning.
- [x] Ordinary and LI-enabled processor/tap paths, remote hunters, documentation,
      translations and required checks are verified and committed.

A journal-only measurement fallback does not satisfy receiver-visible source
export. A working ordinary-filter example does not satisfy task-driven central
selection. Keep those distinctions in the final implementation evidence.

## Implementation evidence

The public policy and media-rule protocols use version 2 for grants; version 1
remains available for ordinary operation and historical validation. Media grants
carry opaque references and immutable signed rules, independently of matcher
membership. The task adapter binds references to protected owner incarnation and
task generation. Target-list reordering also invalidates position-based bindings.

The source extension uses the existing proprietary container with the
TS 103 221-2 §5.3.5 envelope: owner length `9`, ASCII owner `lippy.cat`,
source subtype `1` and value version `2`. The interoperability fix replaces the
initial NUL-prefixed draft; unrelated owners and unknown subtypes remain
independent attributes. It carries bounded UTF-8 node/interface values and
explicit domain presence; capture time retains its existing field. Exact encoded
products are persisted, including their source attribute, before replay. Existing
draft-format journal records retain their original bytes on replay.

Focused regressions cover signed contracts and configuration precedence, task
lifecycle and confirmed recovery, exact capture proof, deferred release, receiver
decoding and journal replay. The task-driven trace is in
`internal/pkg/processor/central_task_capture_integration_test.go`; the hunter
wire/producer/spool trace is in
`internal/pkg/hunter/reliable_media_grants_integration_test.go`. Call and signalling
source replay use `processor_li_capture_source_test.go`; non-call replay uses
`li/delivery/capture_source_replay_test.go` with the existing authorization
fixture, without enabling unsupported raw-IP task types.

The integrated trace runs duplicate suppression off and on. Six live media
observations plus one retained historical copy produce seven receiver products
with suppression off and five with it on. Two corresponding copies are
suppressed. The test includes an overlap longer than its configured evidence
window and separately delayed copies retained outside that window. Detector
counters count each configured consumer separately; they are not wire totals.
Observation, selection, subscriber installation and first admitted media times
are logged separately as measurements, without performance acceptance targets.

Signalling authority remains explicit: the LI trace uses trusted tap-local SIP;
the separate processor trace uses ordinary authorized capture. An LI media-only
grant cannot authorize remote all-SIP forwarding. Segmented TCP source provenance
continues to be checked by the existing VoIP assembler/release tests in addition
to the framed TCP messages in the task-driven trace.

The isolated `make test-ebpf` gate passed live map updates and command admission,
including disabled admission, domain separation, recovery and UDP/TCP negotiation.
Its opt-in exploratory measurement test was not enabled. CUDA linking remains
the existing configured-builder option in `make build-matrix`; no CUDA code is
changed here. Manual checks passed all 47 regressions and all three editions,
with ca/de each fully translated (5842 current messages). The native tool emits
its existing mdBook 0.5.4/0.5.2 compatibility notice; edition builds pass.

## Closure record

**Decision:** `CLOSED` for the implemented feature scope. One independent
review and one integrated post-fix review completed. The single remediation
batch fixed generic shared-owner proof validation at producer admission/sealing
and deterministic offline retry observation. Ten non-race offline runs and the
actual shared-owner producer regression pass; no supplemental finding remains.

Verified gates: `make test`, `make vet`, `make build-matrix`, `make test-ebpf`,
`make manual-check`, `make manual`, and ordinary/LI race suites across capture,
policy/grants, media rules, forwarding, task authority, encoding, persistence,
processor/tap and command settings. After the final producer change, the affected
hunter/forwarding/connection/filtering race suites and full test/vet/build gates
passed. Tests generate their own traffic and protected storage; no private PCAP
files or unavailable capture fixtures are required.

### CI follow-up (2026-10-18)

[CI run 39107669003](https://github.com/endorses/lippycat/actions/runs/39107669003)
exposed an ordering assumption in
`TestCompletedCallClosesThroughRegistryLifecycle`: registry removal becomes
visible before the output-close callback finishes. The test now waits for both
observable effects in one synchronized polling assertion, retaining its existing
completion deadline and exact close-count check. Production lifecycle ordering is
unchanged. The focused test passes 100 repetitions with race detection and atomic
coverage. The complete LI CI command also passes locally:
`go test -v -race -tags='all li' -coverprofile=coverage-li.txt -covermode=atomic ./...`.

### Proprietary attribute interoperability follow-up (2026-10-18)

The corrected owner envelope and version-2 body pass an independent byte vector,
malformed-owner/body, mixed-owner/subtype, duplicate and TLV-boundary regressions.
A 10-second decoder fuzz run and race suites for `internal/pkg/li/...`,
`internal/pkg/processor`, `cmd/process` and `cmd/tap` pass with `all li` tags.
`make manual-check` passes all 47 checks with ca/de each fully translated
(5844 current messages), and `make manual` builds all three editions.
