# Distributed media admission and call continuity implementation plan

**Date:** 2026-10-17

**Status:** Shared feature implementation committed and validated. LI completion
work remains in the follow-up below. The checked tasks and original closure
record describe the implementation assessed at `757719f5`.

**Follow-up (2026-10-18):** Verification identified incomplete task-driven LI
selection privacy and receiver-visible capture-source metadata. The earlier
blanket completion statement was too broad for those end-to-end requirements.
The follow-up implementation and receiver evidence now resolve those gaps;
completion is recorded in
[Central task selection and capture-source export](central-task-selection-and-capture-source-export.md).

**Baseline:** local `main` at `adcf6f43`. Ordered processor failover, reliable
raw-packet forwarding, packet receipts and packet spooling already exist. Extend
and verify their integration with the new features rather than rebuilding them.

## Objective

Let hunters capture different parts of the same call while a processor keeps one
call record and controls which media each hunter captures. A tap provides the
same processing and local capture capabilities in one node.

For example, hunter A sees a selected SIP call, but hunter B sees its RTP. The
processor learns the media endpoints from the signalling and sends B a temporary
media rule. If the RTP later moves to hunter C, C can capture it without waiting
for another SIP exchange. Each packet still records which hunter captured it.

These features support segmented networks, remote monitoring, redundant capture
points and changing traffic paths. They must be usable in the ordinary hunter,
processor and tap builds, using the existing capture, filtering, authentication
and forwarding mechanisms.

## Deliverables

| Feature | User-visible behavior |
| --- | --- |
| Local-only filters | Keep a filter on a processor/tap for central matching instead of distributing it to hunters |
| Remote media rules | A processor tells selected hunters which RTP/RTCP endpoints to capture, with update, expiry and removal |
| Shared call tracking | Local and remotely captured SIP feed one processor call lifecycle |
| Independent capture policies | Select how much SIP to forward separately from how media is selected |
| Capture-path continuity | An existing call can move between hunters without a new SIP/SDP exchange |
| Reliable forwarding integration | Selected packets use existing buffering, receipts, replay and failover correctly |
| Optional duplicate suppression | Reduce repeated observations from overlapping hunters without confusing them with transport retries |
| Source metadata and diagnostics | Preserve hunter/interface/domain/time and expose rule state, drops and duplicate coverage |

Implement these shared features for ordinary capture and LI mode, including the
consumer-specific integration needed for correct call tracking, authorization,
buffering, duplicate handling and delivery. Preserve existing safety and storage
checks while adapting the affected paths.

## Architecture and existing code

Use the existing call registry and admission controller rather than building a
second Call-ID/port tracker. A kernel endpoint match is only a capture candidate;
userspace still checks the exact call, source scope, selection and rule lifetime.

| Responsibility | Existing integration points |
| --- | --- |
| Filter model and distribution | `api/proto/management.proto`, `internal/pkg/processor/filtering/manager.go`, `processor_filter_mutations.go`, `processor_grpc_handlers.go` |
| Local filter matching | `internal/pkg/processor/filtering/target_local.go`, `internal/pkg/hunter/application_filter.go` |
| Call lifetimes and endpoint ownership | `internal/pkg/callregistry/call_registry.go`: `Lifetime`, `EndpointObservation`, `AddEndpointObserver`, `ResolveMediaEndpoints` |
| SIP/SDP processing and cleanup | `internal/pkg/sipflow/`, `internal/pkg/voip/admission/`, `internal/pkg/voip/processor/scoped_adapter.go` |
| Local and remote processor input | `internal/pkg/processor/source/local.go`, `processor_packet_pipeline.go`, `internal/pkg/pipeline/grpcadapter/` |
| Hunter UDP/TCP handling | `internal/pkg/voip/{hunter_sipflow,udp_handler_hunter,tcp_handler_hunter,voip_packet_processor}.go` |
| Userspace and kernel admission | `internal/pkg/mediaadmission/`, `internal/pkg/capture/ebpfadmission/` |
| Packet retention and forwarding | `internal/pkg/hunter/reliable_packets.go`, `internal/pkg/hunter/forwarding/`, `internal/pkg/hunter/packetforwarding/`, `internal/pkg/packetspool/`, `internal/pkg/packetreceipt/` |

Retain the existing behavior documented in the
[failover plan](hunter-processor-failover.md) and
[media admission plan](voip-ebpf-media-admission.md). Read the applicable
`AGENTS.md` files before modifying each area. Do not reopen their completed work
unless a concrete integration defect requires a focused correction.

### One call record across capture sources

Feed tap-local SIP and authenticated hunter-delivered SIP into the same processor
call lifecycle. Reuse existing SDP validation, exact endpoint ownership, call
incarnations, observation domains and trailing-media grace. Associate media with
one authoritative call or leave it unassociated; do not pick a call by recency
or merge the matching filters of several candidate calls.

A hunter's `CallID` or matched-filter list alone does not establish central call
ownership. Validate the source, filter revision and supporting SIP/SDP before
adopting a selection. Local-only filters can select signalling received from a
hunter as well as signalling captured locally by a tap.

A new hunter may see RTP and later BYE without having seen INVITE. Temporary rules
must include enough dialog/lifetime information for the hunter to forward related
signalling to the processor. Central validation still decides whether that message
updates or ends the call. A raw Call-ID match must not bypass existing dialog,
transaction and source checks.

### Local-only managed filters

Add an explicit distribution scope. The protobuf zero value preserves the current
distributed behavior; a new local-only value means matching on this processor/tap.
`TargetHunters` retains its existing meaning within distributed scope, including
empty meaning all hunters. Do not overload an empty list or a special hunter ID
to represent local-only scope.

Apply scope consistently to filter queries, initial snapshots, live updates,
persistence and shared-policy exports. Exclusion happens on the server so older
clients cannot receive a local-only filter by ignoring a field they do not know.
Changing a distributed filter to local-only withdraws its old hunter copies while
retaining local matching.

### Temporary media rules

Use a separate ephemeral media-control service on the existing management
connection. Do not write each call update into the durable managed-filter store.
Reuse existing connection authentication, permissions and capability negotiation.
Accept rule changes only from the configured, authenticated processor controlling
that hunter/source scope.

| Rule field | Meaning |
| --- | --- |
| Processor/session | Which processor and current control generation issued the rule |
| Call reference | Opaque call incarnation, dialog association and selection/filter revision |
| Capture scope | Eligible hunters and an explicit mapping to their observation domains |
| Endpoints | Validated IPv4/IPv6 address and UDP port, RTP/RTCP, both directions and RTCP mux |
| Revision | Ordered updates and explicit removal for this rule lifetime |
| Lifetime | Valid-from and expiry; reconnect does not extend the rule automatically |

Define bounded complete snapshots, updates, removals and application results.
Apply a snapshot only when complete, then apply later updates in revision order.
A queue overflow forces resynchronization rather than silently losing a removal.
Control-generation changes reject callbacks and messages from the old connection.
A restarted hunter needs a current snapshot before using processor-selected media.
Rules are reconstructed from the processor's current call state, not restored
from stale per-call files.

Rules expire in userspace even when the kernel map still contains a stale entry.
Remove expired desired endpoints and report failed kernel updates. Other valid
calls and explicitly configured local capture continue under their own policies.
A runtime admission fallback must not bypass userspace selection or expiry.
Preserve existing stricter capture restrictions in deployments that configure
additional policy; these features do not relax them.

Use configured count, byte, endpoint and subscription limits. Keep monotonic local
expiry deadlines so a backward wall-clock change cannot extend an installed
rule. Define how absolute expiry and clock uncertainty are validated on receipt.
No per-call timers, workers or queues may grow without a configured bound.

### Independent SIP forwarding and media selection

Proposed settings are `hunter.voip.signalling_policy: matched|all|none` and
`hunter.voip.media_policy: local|processor`, with equivalent applicable tap source
settings. Final CLI spelling must follow existing project conventions. Existing
configuration defaults to `matched` plus `local`.

| Policy combination | SIP forwarding | Media selection |
| --- | --- | --- |
| `matched` + `local` | Existing matching and no-filter behavior | Existing local selection; unchanged default |
| `none` + `processor` | No SIP export from this source | Current processor rules; signalling is observed elsewhere |
| `all` + `processor` | Explicitly forward eligible SIP without selecting every call locally | Current processor rules only |
| `matched` + `processor` | Forward locally selected SIP plus validated signalling for already known remote call associations | Current processor rules only |

Keep these settings separate from `--no-filter-policy`. In processor-media mode,
a local match can initiate a call but must not leave a second local media allowance
that survives remote rule expiry or withdrawal. Reject incompatible selectors
that would silently broaden a rules-only mode; retain existing independent
selectors in local-media mode.

All-SIP export requires explicit opt-in. Operator capture predicates remain in
force in every mode. Automatically generated RTP ranges must not reject a valid
remote endpoint; explicitly configured restrictions still apply.

### Source metadata and call continuity

Preserve `PacketDisplay.NodeID`, source interface, observation domain and original
capture time across matching, forwarding, spooling and replay. Processor and
hunter identifiers retain their current roles; no new identity mode or external
identifier is introduced.

Moving media to a different hunter under the same processor keeps the existing
call record, selection and media rules. Processor failover reuses today's transport
behavior; connecting to a different independent processor does not transfer its
call registry automatically. A processor restart does not imply new call-state
persistence as part of this work.

### Optional cross-hunter duplicate suppression

Add an opt-in processor/tap packet-processing option, disabled by default. Place
it after source validation and existing reliable-ingress receipt handling, before
the selected analysis/output processing boundary. Preserve the raw input counters
and bounded evidence of all contributing hunters. Document which consumers see
suppressed packets; do not silently alter capture-file or monitoring behavior.

Duplicate suppression across hunters is different from retry detection for the
same reliable transport record. Keep receipt/replay accounting unchanged even if
two different hunters observed the same packet.

Use a conservative key with observation domain, flow/direction and packet/protocol
identity plus content verification. Exclude mutable routing/link headers
intentionally. Payload equality or RTP sequence number alone is insufficient.
Require distinct authenticated sources; preserve same-source repeats, legitimate
retransmissions, changed content and ambiguous matches. Unsupported packet forms
are retained and counted rather than guessed.

Use one bounded in-flight claim for concurrent equivalent observations. Commit
suppression only when the selected downstream processing owner accepts a copy;
release the claim if admission rejects before acceptance. A rejected first copy
must not suppress a later eligible one. Independent consumers must not lose their
copy because another consumer has already accepted its own copy.

Configure a time window and count/byte limits. Report reduced coverage when replay
arrives beyond the window or capacity is exhausted; retain packets rather than
silently dropping unique observations. Do not introduce a durable global packet
index or claim exactly-once output delivery.

## Implementation steps

### 1. Define shared configuration and protocol contracts

- [x] Confirm the integration points at the implementation revision and preserve
      concurrent edits. Finalize typed configuration and capability negotiation.
- [x] Specify filter scope, media-rule fields, snapshot/update/removal ordering,
      source-domain mapping, bounded resources and unsupported-peer behavior.
- [x] Specify how rules convey validated dialog association for later BYE/UPDATE
      without implicitly enabling all-SIP forwarding.
- [x] Specify rule expiry, reconnect/bootstrap behavior and packet de-duplication
      coverage. Record operational defaults and rationale; do not invent latency,
      throughput, CPU, memory, restart or soak acceptance thresholds.

**Evidence:** the shared contracts and compatibility behavior are concrete enough
to implement and test in ordinary builds.

### 2. Add local-only filter scope

- [x] Extend the management protobuf and typed filter model with a compatible
      distribution scope. Regenerate generated code through `make -C api/proto`.
- [x] Persist and validate the scope through the existing managed-filter mutation
      path, preserving revisions and secure-store commit semantics.
- [x] Apply scope to queries, snapshots, live updates and shared-policy export.
      Keep local matching active for both tap-local and received SIP.
- [x] Withdraw previously distributed copies when scope changes to local-only;
      publish normally for the reverse transition. Do not include hidden filter
      values in removal metadata.
- [x] Expose scope in existing filter create/update/list/show flows and document
      unchanged default behavior. Verify older peers cannot receive local-only
      contents through another export path.

**Evidence:** a centrally configured filter selects the intended call without its
pattern being sent to hunters; scope changes and restart retain that behavior.

### 3. Add the media-rule service and hunter admission adapter

- [x] Implement a bounded ephemeral rule registry/service and client subscription
      using existing management authentication and permissions.
- [x] Implement complete snapshots, ordered updates, explicit removal, expiry and
      stale-control-generation rejection. Overflow forces resynchronization.
- [x] Extend existing exact endpoint/lifetime ownership to install remote rules;
      do not create a separate port-only association table.
- [x] Connect userspace ownership and desired kernel endpoints through the same
      revisioned adapter. Expose partial application and recovery state.
- [x] Use existing eBPF maps without call-triggered capture restart, program/socket
      replacement or `SetBPFFilter`. Keep a correct userspace path when eBPF is off.
- [x] Enforce removal and expiry in userspace even if kernel reconciliation fails.
      Retain explicit capture restrictions and existing configured failure policy.
- [x] Test partial snapshots, stale/duplicate updates, removal races, reconnect,
      expired rules, domain separation, shared endpoints, reused Call-IDs, capacity
      pressure and RTP/RTCP endpoints outside automatic capture ranges.

**Evidence:** authenticated remote rules affect admission and call association
consistently, expire safely and recover through snapshots.

### 4. Add the common processor call tracker and rule publisher

- [x] Feed local and authenticated hunter-delivered SIP into the same selected-call
      lifecycle. Reuse existing parser, SDP validation and endpoint observations.
- [x] Validate selection evidence and filter revision before adopting a hunter's
      call; apply processor-local filters to remotely observed signalling.
- [x] Publish rules from selected endpoint/lifecycle changes, including both media
      directions, RTCP, revision and configured trailing-media grace.
- [x] Distribute rules to all eligible hunters within the enabled profile by
      default, with explicit hunter scoping available. New subscribers receive
      the current state without waiting for another SIP event.
- [x] Preserve one call record when signalling/media switch hunters. Prevent local
      and remote observations of the same call from creating publication loops.
- [x] Give tap equivalent local processing without an artificial hunter-to-local-
      processor gRPC connection.

**Evidence:** INVITE at A can select RTP at B, then RTP at C with unchanged
endpoints and no new SIP; the processor retains the same call lifecycle.

### 5. Add independent signalling and media policies

- [x] Implement the four documented combinations with existing defaults unchanged.
      Keep protocol policy separate from no-filter and delivery-profile settings.
- [x] Apply policies to immediate UDP handling, TCP reassembly and buffered packet
      release. Do not let all-SIP forwarding select all media implicitly.
- [x] Use remote call associations to forward validated later signalling from a
      hunter that never observed INVITE; centrally validate BYE/UPDATE before
      changing the call's endpoints or lifecycle.
- [x] Verify local media allowances cannot bypass remote removal/expiry in
      processor-media mode. Reject conflicting capture selectors visibly.
- [x] Verify local-only filtering with signalling captured by a tap and with
      signalling explicitly forwarded by hunters. Cover both UDP and TCP.
- [x] Test INVITE through A, RTP through B, and BYE through B with no local INVITE
      history. Rule retirement and trailing grace must follow the central call.

**Evidence:** each policy captures only its intended signalling/media and supports
ongoing calls without broadening to unrelated traffic.

### 6. Verify reliable forwarding and disconnected operation

Ordinary reliable VoIP forwarding already has producer hooks for accepted
asynchronous/buffered packets. Verify and complete this integration; do not treat
reliable packet transport as missing or remove restrictions for unrelated modes.

- [x] Verify immediate UDP packets, buffered releases and asynchronous TCP output
      use the existing reliable producer when that delivery profile is enabled.
- [x] Retain packet origin/session/batch identities, source metadata and capture
      timestamps through storage, resend and verified receipts.
- [x] On disconnect, keep remote rules only until their existing expiry. Stop new
      remote-selected media when no valid rule remains; preserve independent
      local capture policies and other valid calls.
- [x] Keep packets already accepted into the spool under its existing retention
      and replay contract. Replaying them does not renew a media rule or re-arm
      current capture. Preserve downstream validation and output checks.
- [x] Reconcile current rules after reconnect using a complete snapshot. Reuse
      existing failover, receipt scope, TLS requirements, storage protection and
      overflow/loss reporting without downgrade.
- [x] Test disconnect during capture, expiry during buffered release, delayed TCP
      completion, spool overflow, restart/replay and route replacement. Distinguish
      accepted backlog from packets excluded by current selection.

**Evidence:** the new policies compose with today's best-effort and reliable
forwarding profiles; retained packets and current capture state remain distinct.

### 7. Add optional cross-hunter duplicate suppression

- [x] Define the packet-processing boundary and document exactly which analysis,
      capture-file and monitoring consumers are affected by explicit activation.
- [x] Implement bounded canonical comparison, content-conflict detection and
      conservative handling of unsupported/ambiguous observations.
- [x] Add transactional in-flight ownership; release claims on pre-acceptance
      failure and retain independent consumer delivery.
- [x] Preserve source metadata and raw observation counts. Report suppression,
      ambiguous retained packets, capacity pressure and window coverage separately
      from reliable-transport retries and downstream queue drops.
- [x] Test concurrent copies, first-copy rejection followed by alternate-source
      acceptance, same-source repeats, legitimate retransmissions, changed content,
      different domains/flows, RTP wrap and replay inside/outside the window.

**Evidence:** supported repeated observations are reduced when explicitly enabled,
while unique traffic, legitimate repeats and independent consumers remain intact.

### 8. Add operational visibility, documentation and end-to-end coverage

- [x] Expose rule readiness, control generation/revision, active calls/endpoints,
      pending synchronization, expiry/removal, stale updates and application errors
      through existing status mechanisms. Keep metric labels bounded.
- [x] Preserve original hunter/interface/domain/time in packet displays, capture
      metadata and diagnostics through the existing representations.
- [x] Add synthetic multi-hunter fixtures with stable endpoint addresses, changing
      observation paths and overlap. Exercise a late-joining hunter, media arriving
      before a rule, delayed control updates and loss of the processor connection.
- [x] Verify processor and tap parity, older-peer behavior and clear rejection of
      explicitly requested unsupported features. Use invented identities and
      reserved example addresses.
- [x] Integrate and verify the same features in LI-enabled processor/tap builds,
      including current task authorization, expiry, reliable VoIP forwarding,
      per-task duplicate handling and call/delivery continuity. Make the required
      consumer changes without coupling shared capture components to LI.
- [x] Update command documentation and configuration examples for local-only
      filters, SIP/media policies, temporary rules, expiry and duplicate suppression.
- [x] Update affected manual source and every language configured in
      `docs/manual/languages.json` following `docs/manual/README.md`. Translate new
      and changed entries, review affected fuzzy entries, then run
      `make manual-check` and `make manual`.
- [x] Record actual tests and any capture-loss/installation-delay observations.
      Performance observations are exploratory unless an existing sourced
      requirement establishes a threshold.
- [x] Format changed files before staging, check off only verified tasks, and
      commit implementation changes with the updated plan. Preserve unrelated
      edits and name files by responsibility rather than step number.

## Validation and completion

Run targeted tests during implementation, then the appropriate repository checks:

```bash
go test -tags all ./internal/pkg/callregistry/... ./internal/pkg/mediaadmission/...
go test -tags all ./internal/pkg/hunter/... ./internal/pkg/processor/...
go test -race -tags all ./internal/pkg/hunter/... ./internal/pkg/processor/...
make test
make vet
make build-matrix
```

Extend the existing `make test-ebpf` isolated tests for live map updates, removal,
expiry and explicit capture predicates. Generic namespace/container fixtures may
use `tc netem` for delayed or disconnected links. Ask before running tests outside
the sandbox as required by the workspace instructions. Do not mark privileged or
external tests complete when they have not been run.

Completion means these features work in ordinary hunter, processor and tap builds:
local-only filtering; remote media rules; central call tracking across hunters;
all documented signalling/media policy combinations; existing reliable forwarding;
optional duplicate suppression; and preserved source metadata/status. Existing
consumer checks, resource limits and storage contracts remain intact. The same
features must work with LI enabled, including the necessary capture and delivery
integration, before the full plan is complete.

Prefer existing dependencies and tooling. If a new dependency is necessary, select
the latest stable compatible release at implementation time and document any
compatibility exception. Do not expand this work into a dependency-upgrade project.

## Implementation evidence

The implementation provides local-only managed filters, authenticated temporary
media rules, shared call tracking, independent signalling/media policies,
reliable-forwarding integration, optional per-consumer duplicate suppression,
and source metadata/status in ordinary and LI-enabled builds. Shared capture and
control packages use lippycat concepts; LI integration remains in its existing
build-tagged consumers.

Protobuf generation through `make -C api/proto` succeeds. Focused ordinary and LI
race suites verify filter scope/persistence, media-rule ordering and resource
limits, actual authenticated hunter subscriptions, hunter/tap UDP/TCP/buffered
capture policies, and central call selection. The central integration covers a
local-only filter, INVITE at A, RTP at B and C without a new SIP exchange, later
BYE at C, late subscriber synchronization, retained source/time/domain metadata,
and immediate filter revocation. Dialog, incarnation and endpoint ambiguity
checks remain authoritative.

Reliable-forwarding tests use real mTLS streams, encrypted origin/custody stores,
signed capture policy and verified receipts. They cover delayed UDP/TCP release,
expiry, same-ID selector replacement, accepted backlog, restart and replay.
Historical or duplicate transport records cannot acquire current rule-publication
authority. Existing secure-store ancestor ownership and protection checks remain
unchanged; the user approved running tests outside the sandbox whose ancestor
ownership differs from the host.

Duplicate detection is disabled by default. Its focused race tests and malformed
packet fuzzing verify bounded conservative comparison and transactional ownership.
Consumer tests cover queue rejection, independent outputs, subscriber eligibility,
call incarnation, virtual-interface conversion, and per-task LI authorization.
LI tests verify current task checks, expiry, shared ordered sequence assignment,
identical destination fanout bytes, ordinary/persistent delivery and original
hunter metadata across capture-path changes.

Observation-domain metadata survives both offline storage paths, summary/detail
reads, cache eviction and query pages, including known domain zero. The oracle
format is explicitly version 5 and the compact format is 2.4. Readers reject
unsupported versions under the existing temporary-dataset contract; there is no
implicit reinterpretation of older records. The complete offline race suite
passes.

### Fixture repair

The first broad run exposed pre-existing tests that expected ignored external
captures. The user authorized fixing that dependency. Commit `b044038b` replaces
it with deterministic generated PCAPs in test-owned temporary directories. All 26
comprehensive protocol cases now run, including 120 sequenced RTP packets, with
protocol and packet-count assertions active. Related SIP/SDP, TCP filtering and
offline replay regressions also execute without developer-specific captures.
Detector, capture and VoIP race checks pass, and the PCAP benchmark executes
without an external file. Explicitly opt-in private-capture coverage remains
supplemental. `CONTRIBUTING.md` documents this fixture policy.

### Final validation and closure

The following required checks pass:

```text
make test
make vet
make build-matrix
make test-ebpf
make manual-check manual
```

The final test and build-matrix runs include the closure fixes. The default build
matrix validates ordinary and LI role partitions; optional CUDA linking was not
requested or run. The privileged eBPF gate passes in its disposable container,
including live remote-rule add/update/removal/expiry with shared endpoints,
reused lifetimes and stable capture program/socket ownership. Its optional
measurement test remains opt-in; no performance threshold is claimed.

The manual check passes 47 tests, and English, Catalan and German editions build
with the changed translations complete. The existing nonfatal mdBook/preprocessor
version notice remains; no dependency upgrades were needed.

One bounded closure discovery and one integrated post-fix review identified and
resolved two material findings. Hunter-authorized empty-ID filter queries now
exclude local-only contents; administrative list/show uses the existing separate
query API, with no hunter-query fallback. Application status is now bounded by
live subscription ownership, so disconnected hunters release capacity and an old
stream cannot delete an overlapping replacement's status. Production gRPC role
checks and subscription lifecycle regressions pass under the race detector,
including the LI-enabled query build. The integrated review found no further
material defects; no supplemental remediation batch was needed.

**Original closure decision (at `757719f5`):** `CLOSED`. Implementation and updated
plan committed in `bb991f88`; fixture repair committed separately in `b044038b`.
The 2026-10-18 verification qualified that completion claim. The remaining LI
selection-privacy and source-export work is recorded in the follow-up plan linked
at the top of this document.
