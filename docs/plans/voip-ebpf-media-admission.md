# VoIP eBPF Media Admission Implementation Plan

**Date:** 2026-10-02

**Status:** Planned; implementation has not started

**Source:** [Selective VoIP Media Capture with eBPF](../research/voip-ebpf-media-admission.md), including its second opinion and subsequent runtime-failure discussion.

## Objective and scope

Add explicitly enabled Linux kernel media admission to `lc hunt voip` and
`lc tap voip`. Keep libpcap as the packet reader, attach one composed eBPF socket
filter, and update endpoint maps as selected calls change. Reject unrelated media
before capture delivery without restarting capture for call activity.

This plan resolves the research's backend choice in favor of libpcap-first and
incorporates the agreed qualifications to runtime fail-open. The research remains
the rationale; this file is the implementation checklist. All unchecked tasks are
future work, not claims of completed verification.

### Required behavior

| Concern          | Contract                                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Activation       | Off by default; available only for hunter/tap VoIP live capture.                                                                                  |
| Call selection   | Admit endpoint candidates only after authoritative selection; retain bounded preselection SDP metadata, not pre-match RTP history.                |
| Kernel authority | Admission is an optimization. Userspace remains authoritative for ownership, selection, expiry, authorization, and output attribution.            |
| Call churn       | Map updates only: no `SetBPFFilter`, program replacement, socket replacement, or capture restart per call.                                        |
| Backend          | Attach to existing libpcap-owned Linux sockets using a supported binding extension.                                                               |
| Scope            | Share admission across interfaces in one observation domain; explicitly isolate overlapping domains.                                              |
| Startup failure  | An explicitly enabled feature that cannot initialize returns an error.                                                                            |
| Runtime failure  | Default to visible, scoped broad media admission; retain explicit capture restrictions and userspace checks. Operator may choose closed behavior. |
| Recovery         | Restore enforcement only after the complete current eligible set is reconciled with concurrent lifecycle changes.                                 |
| Unknown packets  | No packet-triggered transition that opens an entire domain. Use explicit packet-local compatibility rules for supported forms.                    |
| Shadow mode      | Explicit diagnostic mode, separate from degraded operation; timing-aware evidence rather than aggregate-counter correctness claims.               |

### Scope boundaries

Keep existing libpcap capture as the default and preserve other commands. Native
AF_PACKET capture, XDP, hardware offload, project-wide cgo removal, a new general
capture framework, and a userspace pre-filter product are outside this work.
A direct backend is a separate decision only if a concrete integration limitation
is demonstrated. Cgo does not disable goroutine parallelism.

The user-provided 100 calls/s scenario is workload context. There is no new
throughput, latency, CPU, RSS, or soak acceptance threshold. Performance data is
exploratory; correctness, authorization, expiry, and configured resource limits
remain required.

## Architecture and ownership

```text
libpcap-owned live socket
  -> explicit capture restrictions
  -> signaling / compatibility / independent selector admission
  -> per-domain mode + selected endpoint membership
  -> existing libpcap reader and capture pipeline
  -> existing userspace attribution and output selection

validated SIP metadata -> bounded preselection store
authoritative selection + accepted endpoint associations + lifecycle
  -> shared admission controller
  -> desired/installed map state and per-domain recovery
```

The composed filter must apply explicit restrictions before any shadow, degraded,
or compatibility bypass. Separate automatically generated broad RTP ranges from
operator restrictions; otherwise the old range can accidentally defeat learned
endpoints, or a bypass can accidentally widen the user's explicit capture scope.

Proposed new packages and files are named by responsibility, not plan phase:

| Responsibility                                                    | Location and existing integration points                                                                                    |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Neutral config, endpoint keys, ownership/controller, fake backend | New `internal/pkg/mediaadmission/`; avoid importing capture, transport, or command packages here.                           |
| Linux maps, program loading, parser, filter composition           | New `internal/pkg/capture/ebpfadmission/`, with Linux implementation and unsupported-platform stubs.                        |
| Capture installer and handle lifetime                             | `internal/pkg/capture/capture.go`, `pcaptypes/live.go`, and capture options; retain `*pcap.Handle` as the reader.           |
| Stable lifecycle identity and endpoint observations               | `internal/pkg/callregistry/call_registry.go`, `internal/pkg/sipflow/orchestrator.go`, and topology adapters.                |
| Hunter UDP/TCP integration                                        | `internal/pkg/voip/{hunter_sipflow,udp_handler_hunter,tcp_handler_hunter,buffermanager,calltracker,rtp}.go`.                |
| Tap UDP/TCP integration                                           | `internal/pkg/voip/processor/`, `internal/pkg/processor/source/local.go`, and tap runtime composition.                      |
| Configuration                                                     | `cmd/hunt/{voip,config}.go`, `hunter.Config`, `cmd/tap/{tap_voip,runtime}.go`, `source.LocalSourceConfig`.                  |
| Independent selectors                                             | `internal/pkg/hunter/application_filter.go`, hunter filter manager, and `internal/pkg/processor/filtering/target_local.go`. |
| Status and diagnostics                                            | Capture telemetry, hunter stats, local-source stats, management protobuf/status adapters, and `internal/pkg/statusclient/`. |
| Integration and build support                                     | `test/`, `Makefile`, `.github/workflows/integration-tests.yml`, generated eBPF objects/bindings.                            |

The controller owns desired admission, installed-state tracking, retries, and
reconciliation. Libpcap owns its socket descriptor. The capture session owns the
program/map handles and attachment generation. Do not close a borrowed descriptor
or access it after its owning handle has closed.

### Configuration contract

Implement these command options and equivalent settings below
`hunter.voip.rtp_ebpf` and `tap.voip.rtp_ebpf`:

| CLI                         | Config member    | Default / meaning                                    |
| --------------------------- | ---------------- | ---------------------------------------------------- |
| `--rtp-ebpf`                | `enabled`        | `false`; explicit feature activation.                |
| `--rtp-ebpf-mode`           | `mode`           | `enforce`; alternative `shadow` requires activation. |
| `--rtp-ebpf-failure-policy` | `failure_policy` | `open`; alternative `closed`.                        |

Use one typed parser/validator and existing command config precedence. Defining a
mode or failure policy must not implicitly enable the feature. A backend flag is
not required. Unsupported platform, offline input, incompatible configuration, or
unavailable required capabilities must produce a clear error when enabled.

The same typed configuration also contains observation-domain assignments,
endpoint capacity, pending-metadata limits/expiry, bounded update/retry resources,
shadow evidence bounds, and the missing-media diagnostic interval. Expose advanced
settings through YAML first. Reuse applicable existing call/association limits
where possible; record actual new defaults and rationale during implementation.
Defaults are resource settings, not performance acceptance targets.

## Phase 1: Establish attachment and policy composition

Resolve the narrow libpcap integration before implementing a new capture backend.
This phase ends with a reproducible attachment/decision test and a selected binding
strategy, not an open-ended comparison of backend prototypes.

- [ ] Inspect the implementation baseline and preserve concurrent work. Re-read
      lifecycle sources before modifying them; do not revert or absorb unrelated
      edits into this feature.
- [ ] Add a supported Linux live-handle attachment operation to the pinned
      gopacket binding or a narrowly scoped maintained replacement. Record the
      exact revision, patch, license, and reproducible dependency provisioning.
      The current v1.1.19 handle has a private C pointer and no public attachment
      API; reflection or unsafe extraction of that private field is excluded.
- [ ] Use `cilium/ebpf` for loading and map management, selecting a version
      compatible with the project's Go/build requirements. Add source and
      reproducible `bpf2go` generation; ordinary builds/runs consume embedded
      objects and do not require a runtime C compiler.
- [ ] Verify one socket program can compose explicit capture restrictions with
      admission. Evaluate libpcap classic-BPF compilation plus a translator such
      as `cbpfc` against the actual socket-filter context before selecting it.
      Preserve compilation inputs including link type, snap length, and netmask.
- [ ] Compare translated predicate decisions with libpcap evaluation on synthetic
      Ethernet, supported cooked-link, VLAN/offload, IPv4/IPv6, fragment, truncated,
      and encapsulated fixtures. Verify accepted packets retain the configured
      capture length. Reject unsupported expressions/link types at startup rather
      than silently substituting a different predicate.
- [ ] Establish compatible libpcap userspace filter state. Test that previously
      stored classic filters and buffered-block filtering cannot reject newly
      admitted media unexpectedly. Do not simply attach eBPF over an incompatible
      restrictive libpcap filter and assume all filtering has moved to the kernel.
- [ ] Define and test the activation-to-attachment boundary: classify or discard
      pre-attachment buffered packets deliberately; attaching eBPF does not imply
      the mmap ring was flushed. Do not report readiness before policy is active.
- [ ] Record the supported kernel features, privileges, architectures, link types,
      and libpcap behavior from this test. If a real blocker requires a different
      backend, report it and revise this bounded design decision before expanding
      into native AF_PACKET work.

**Completion evidence:** a live libpcap handle receives/discards the expected test
packets; adding/removing an endpoint changes reception on the same socket/program;
explicit restrictions survive every tested admission mode.

## Phase 2: Implement controller identity, scope, and bounded state

This phase can develop against a fake map backend while Phase 1 establishes the
kernel integration. Its state contract is shared by hunter and tap.

- [ ] Define endpoint keys as observation domain, address family, normalized IP,
      and UDP port. Assign domains consistently in packet metadata, call ownership,
      and kernel lookups; default one domain across a process's capture interfaces.
- [ ] Implement explicit domain separation without leaving authoritative userspace
      association keyed only by an unscoped endpoint/Call-ID. Use scoped registry
      identities or per-domain instances as the existing composition permits;
      verify both SIP and media arriving on different interfaces in one domain.
- [ ] Define immutable capture-session and call/dialog lifetime identities. The
      registry's current recency counter changes on touch and is not a lifetime
      generation. Carry stable identities through additions, removals, metadata
      promotion, retries, and delayed completion callbacks.
- [ ] Add a narrow endpoint/lifecycle observation contract with immutable snapshots
      and no kernel operations under registry locks. Existing start/end observers
      alone do not expose all endpoint changes. Only publish associations accepted
      by authoritative registry limits, including `TryAssociateEndpoint` results.
- [ ] Maintain distinct eligible owner sets and endpoint membership. Deduplicate
      repeated SDP, insert on first eligible ownership, and delete only after the
      last owner leaves. Preserve ambiguity handling in userspace.
- [ ] Track desired versus installed state, including generation and operation
      failures. Bound queues/retries; a lost or rejected update must mark its scope
      unsynchronized and enter the configured failure policy rather than disappear.
- [ ] Serialize reconciliation and mode transitions per scope. Do not mistake
      per-entry atomicity for atomic multi-endpoint publication. Expose pending and
      installed generations so tests and diagnostics can identify the actual
      publication interval.
- [ ] Cover duplicate observations, shared endpoints, forked/multiple legs,
      reused Call-IDs, stale retries/deletes, capacity limits, observer reentry,
      cancellation, and concurrent selection/finalization with unit and race tests.

**Completion evidence:** deterministic controller tests show that one owner cannot
remove another's admission, stale work cannot modify a new lifetime, and every
uninstalled desired change is observable.

## Phase 3: Implement the kernel admission policy

- [ ] Create a bounded ordinary endpoint hash map, independent exact-address and
      prefix maps, preallocated per-domain control state, and admission counters.
      Avoid LRU eviction of active endpoint entries; expose capacity errors.
- [ ] Implement explicit restrictions first, followed by signaling/compatibility,
      independent selector/no-filter policy, and selected endpoint membership.
      Domain degradation and shadow mode bypass only dynamic media rejection.
- [ ] Check both source and destination endpoints; a match admits a candidate and
      supplies no Call-ID, filter provenance, or authorization decision.
- [ ] Preserve configured SIP discovery and complete TCP reassembly input. Define
      arbitrary-port behavior explicitly: do not silently reduce it to port 5060.
      Where a lightweight parser cannot safely exclude signaling, use documented
      packet-local compatibility admission within the explicit capture predicate.
- [ ] Keep explicit `--filter`, `--udp-only`, SIP-port, and RTP-range intent separate
      from generated capture defaults. Specify and test how an explicitly provided
      RTP range constrains the new mode; never silently reinterpret it as a default
      heuristic range. Handle the current no-filter policy without accidental
      deny-all or broad admission merely because one selector family is empty.
- [ ] Handle IPv4 fragmentation and IPv6 extension/fragment chains with bounded
      parsing and deliberate compatibility decisions. Preserve SIP/SDP reassembly;
      non-initial UDP fragments do not contain UDP ports.
- [ ] Preserve supported VXLAN and enabled ESP-NULL paths. Start with explicit
      packet-local admission where inner endpoints cannot be checked safely; count
      these bypasses and document their effect on selectivity. Include ESP inside
      VXLAN and VLAN offload metadata in fixtures. Do not parse/decrypt full SIP or
      ESP content in the kernel for this feature.
- [ ] Treat malformed/unknown forms according to a documented packet decision;
      one such packet must not toggle an observation domain into degraded-open.
      A confirmed inability to maintain the scope's policy is a controller event.
- [ ] Preserve RTP/RTCP, separate RTCP endpoints, multiplexing, IPv4/IPv6, and
      supported multi-stream SDP semantics through shared endpoint normalization.
- [ ] Validate map/program feature support at initialization. Add kernel program
      decision tests where supported, plus real socket tests; neither replaces the
      other. Generated objects must match the checked-in source.

**Completion evidence:** supported packet fixtures match the documented predicate,
including independent selectors and compatibility bypasses, with observable reasons
for admission/rejection and no change to host traffic forwarding.

## Phase 4: Wire libpcap sessions and command configuration

- [ ] Add an optional installer/session through existing `CaptureOptions`. Route
      both filter installation sites in `capture.go` through it: the readiness path
      and the legacy interface path. Enabled sessions must not later fall through
      to `SetBPFFilter`; disabled/offline behavior remains unchanged.
- [ ] Serialize setup, attachment, statistics access, and close with handle
      ownership. Release owned program/maps after readers stop; close all partial
      initialization resources and propagate errors with context.
- [ ] Change opt-in hunter startup to wait for capture readiness and return
      attachment failure. Its current manager launches `InitWithBuffer` and returns
      before initialization; reuse the readiness mechanism already used by tap.
- [ ] If one interface fails during multi-interface initialization, unwind the
      entire requested enabled capture session; do not report partial success.
- [ ] Share domain maps across the appropriate sockets. On genuine configuration
      restart or handle recreation, attach current policy and reconcile state before
      readiness. Keep per-call updates outside existing restart paths.
- [ ] Implement the common typed configuration and the three CLI options above
      only on the VoIP hunter/tap commands. Test defaults, YAML/CLI precedence,
      explicit disable, invalid enums/limits, unsupported platforms and offline use.
- [ ] Add Linux implementations and platform stubs. An ordinary disabled build/run
      must not need BPF privileges, load programs, or allocate the new state.
- [ ] Test startup failure injection, compatible libpcap filter state, buffered
      startup packets, descriptor ownership, restart reattachment, and shutdown
      using existing capture readiness/lifecycle injection points.

**Completion evidence:** both commands meet the same opt-in/startup contract, and
socket/program identity remains stable during endpoint churn.

## Phase 5: Wire SIP selection, SDP retention, and lifecycle

- [ ] Add bounded metadata observation after shared parsing and security validation
      but before an unmatched SIP message returns filtered. Retain normalized SDP
      endpoints and dialog/transaction identity, not payload or packet history.
- [ ] Bound retained dialogs, endpoints, bytes, TTL, and expiration work. Reuse
      existing validated SDP parsing where possible; unify duplicate normalization
      used by tracker/buffer manager/processor so kernel admission cannot disagree
      with userspace attribution. Report metadata eviction and unavailable late
      promotion explicitly.
- [ ] Define the authoritative transition to eligibility once for each existing
      composition. Registry existence, sticky SIP selection, buffer-manager match
      state, and an answer are not interchangeable. Selection plus accepted endpoint
      knowledge is required; an answer is not required for eligible early media.
- [ ] Promote retained metadata on later selection using tags, transaction identity,
      CSeq/branch, and lifetime generation as appropriate. Prevent old/forked offers
      from being promoted into a different dialog. Do not retroactively capture RTP.
- [ ] Inject the same controller/store into hunter UDP and reassembled TCP paths;
      preserve sticky selection and terminal-response forwarding.
- [ ] Inject the same controller/store into tap UDP and reassembled TCP paths,
      local-source selection, and finalization. Only local capture observations may
      seed these maps; remotely received processor calls must not install local
      admission solely because they share the process.
- [ ] Handle offer/answer, provisional SDP, delayed offers, re-INVITE/UPDATE, rejected
      renegotiation, hold/disabled streams, multiple legs and endpoint reuse. Define
      endpoint retirement relative to current behavior, which accumulates entries;
      do not silently remove a still-valid opposite-side or previous endpoint.
- [ ] Remove eligible ownership on authoritative finalization, expiry, eviction,
      and shutdown, honoring existing trailing-media grace and generation checks.
      Preserve filter revocation/expiry and existing userspace authorization even
      while stale candidates or degraded admission reach userspace.
- [ ] Update independent selector maps from authoritative filter mutations. Match
      direct/inherited provenance and the no-filter policy in both topologies.
- [ ] Add parity tests across UDP/TCP and hunter/tap for late selection, signaling
      before SDP, shared/ambiguous endpoints, trailing media, and scope separation.

**Completion evidence:** both topologies derive the same eligible endpoint set from
equivalent input, while existing output selection remains authoritative.

## Phase 6: Implement explicit degradation and recovery

| Effective state | Behavior                                                                                                |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| Disabled        | Existing capture; no admission resources.                                                               |
| Initializing    | No successful readiness until required policy/resources are ready.                                      |
| Shadow          | Explicit restrictions enforced; dynamic decisions recorded but do not reject media.                     |
| Enforcing       | Dynamic media admission active.                                                                         |
| Degraded-open   | Affected scope bypasses dynamic media rejection; all explicit restrictions and userspace checks remain. |
| Degraded-closed | Do not bypass rejection; keep valid installed admission and report missing/unreconciled state.          |
| Recovery        | Reconcile the complete desired set while retaining the configured degraded behavior.                    |
| Control-failed  | Requested transition could not be established; report last confirmed and uncertain effective state.     |

- [ ] Default enabled runtime failure policy to open, with an explicit closed
      option. Trigger on confirmed failed required updates, capacity exhaustion,
      or lost synchronization; do not open a whole scope from one unknown packet
      or a missing-media alert.
- [ ] Use separate preallocated per-domain control state so switching to open does
      not require insertion into the full endpoint map. Test control-update failure
      separately; never claim broad reception was established if that write failed.
- [ ] Degrade the affected observation domain, narrowing further only where policy
      and packet ownership support it. Do not narrow solely to the interface that
      carried SIP when the domain's media can arrive on another interface.
- [ ] Keep mode transitions bounded and coordinated with concurrent call changes.
      Retry/reconcile without an unbounded queue or global per-packet scan. Expose
      sustained degradation; do not promise it ends while the cause persists.
- [ ] Restore enforcement only after additions, deletions, eligibility changes,
      and generations match a consistent current snapshot. One successful retry
      or freed map slot does not establish recovery. Test changes racing the final
      transition and prevent repeated stale work from restoring enforcement.
- [ ] Preserve explicit restrictions in open and shadow states. Opening admission
      must not bypass authorization, output selection, expiry, or resource limits.
- [ ] Expose entry/exit logs, reason, configured/effective mode, time open, packets
      admitted while open, failed transitions, pending updates, and recovery counts.
- [ ] Fault-inject full maps, failed insertion/deletion, failed mode writes, missed
      updates, concurrent revocation, stale retries, and controller shutdown.
      Verify both open and closed policies without restarting capture per failure.

**Completion evidence:** injected failures cannot masquerade as normal operation,
and recovery never enables enforcement against an incomplete current owner set.

## Phase 7: Add shadow evidence and operator visibility

- [ ] Record kernel decision reasons and scope/policy generation. For correlated
      shadow evidence, use bounded diagnostic events and deterministic synthetic
      packet IDs in tests; for live samples, account for duplicates/collisions,
      clock correlation, sampling, and lost events rather than claiming exact proof.
- [ ] Distinguish expected pre-selection rejection, selection-to-publication loss,
      and unexpected rejection after confirmed publication. Re-reading the map
      later is not evidence of its earlier decision.
- [ ] Keep evidence collection bounded and optional outside diagnostic mode. Count
      incomplete evidence and avoid logging packet payloads or sensitive selector
      values in ordinary status. Shadow load/state can differ from enforcement;
      record that limitation in results.
- [ ] Add selected/answered-without-media diagnostics with a configurable interval.
      Separate installed endpoints, admitted candidates, and final attributed
      media. Treat hold/inactive streams and observation placement as possible
      explanations; an alert must not automatically widen reception.
- [ ] Add a common typed status snapshot and wire it through capture heartbeats,
      hunter stats, tap local-source stats, management status, and CLI JSON. Extend
      protobuf fields additively and regenerate using existing tooling if needed;
      test nonzero values and unknown/default behavior with older peers.
- [ ] Include endpoint capacity/occupancy, pending metadata expiry/eviction,
      compatibility-pass counters, scope state, update errors, shadow evidence loss,
      and publication timing. Preserve existing capture-drop counter meanings.

**Completion evidence:** operators can distinguish disabled, shadow, enforcing,
degraded, recovering, and failed-control states for hunter and tap.

## Phase 8: Verify, document, and complete

- [ ] Add isolated Linux socket/libpcap integration tests under `test/` with
      synthetic traffic and namespaces/veth where appropriate. Exercise both
      commands, multiple interfaces, selected/unselected calls, multiple legs,
      independent selectors, no-filter mode, VLANs, fragments, VXLAN/ESP, startup
      buffering, and map-only updates on a stable socket.
- [ ] Add end-to-end failure/recovery cases and verify output attribution is
      unchanged across shadow, enforcement, and degraded modes except for the
      documented absence of pre-match/admission-window media.
- [ ] Provide an explicit privileged integration entry point/job. Missing kernel
      support or privileges must be reported as not exercised, not as passing
      evidence. Ask for test escalation when sandbox restrictions require it.
- [ ] Run focused controller/lifecycle/capture race tests, then the project-required
      `make test`, `make vet`, and `make build-matrix`. Verify ordinary builds use
      embedded BPF objects and disabled/non-Linux paths remain usable. Include
      relevant `all,li` hunter/tap output-authority coverage without weakening LI.
- [ ] Measure broad capture, shadow, and enforcement using equivalent synthetic
      traffic, including 100 calls/s, varied match fractions, legs, and lifetimes.
      Record CPU/allocations, delivery/drop counts, queue pressure, map occupancy
      and update failures, full SDP-arrival-to-publication timing, and initial media
      loss. Describe environment and compatibility bypasses; add no invented gates.
- [ ] Update hunter/tap README and architecture docs, manual configuration/command
      references, and relevant capture/performance guidance. Document opt-in,
      platform/privilege requirements, all failure states, scope configuration,
      arbitrary-port and encapsulation behavior, limits, and the remaining cgo
      dependency. Keep the research linked as rationale.
- [ ] Record verification commands, results, and unexercised environments in this
      plan or a linked implementation-results document. A userspace pre-filter
      benchmark is optional; a live production rollout is not required to finish
      the implementation and must not be reported as performed without evidence.
- [ ] Format affected files and generated artifacts, check links/diffs, and review
      changes against the contracts above. Check off only actually completed tasks.
- [ ] Commit implementation, tests, documentation, and the verified plan updates
      together in coherent commits, preserving unrelated work. Use descriptive
      filenames rather than names derived solely from phase numbers.

## Dependencies and completion rule

Phase 1 establishes a viable attachment/composition path. Phase 2 can proceed
independently against fakes; Phase 3 consumes its map contract. Phase 4 integrates
the working installer; Phase 5 connects authoritative state. Phase 6 implements
failure/recovery before enabled enforcement is considered complete. Phase 7 makes
shadow/degraded behavior assessable, and Phase 8 records cross-topology evidence.

Correctness test failures must be resolved before completion. Unsupported optional
platforms must have explicit diagnostics and accurate coverage statements. An
exploratory performance result alone does not authorize another optimization cycle
or prevent completion. Do not add mandatory follow-up work or a production rollout
merely to meet an agent-selected performance target.
