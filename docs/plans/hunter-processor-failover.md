# Hunter processor failover implementation plan

**Date:** 2026-10-15

**Status:** Implemented on `feat/processor-failover` for the documented profiles; remaining optional validation and TLS-key work are listed below

**Research:** [Hunter processor failover and handover](../research/hunter-processor-failover.md)

**Inspected implementation:** `7497d44ac842937ea319050f1eec8916443a3d44`

## Objective

Allow a hunter to use an ordered list of processors, maintain one active
connection, and select another candidate when connection or reconnection fails.
The feature must support ordinary capture, analysis, monitoring, PCAP collection,
and supported normalized-event forwarding without LI dependencies.

Support independent destination processors and, separately, intermediate
processors forwarding to a common upstream. Both redundant direct endpoints and
hierarchical deployments use the same general selection mechanism.
Expose stronger delivery guarantees and shared filter policy as explicit options.
LI adds consumer-specific authorization and delivery checks in an optional stage.

Implementation was authorized after creation of this plan. Leave tasks unchecked
until their behavior and required checks have actually been verified.

## Scope, milestones, and dependencies

| Milestone                         | Phases | Delivered capability                                                                                                  | Dependencies and release boundary                                                                                                       |
| --------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| General hunter failover           | 0–3    | Ordered candidates, bounded attempts, sticky active destination, packet/event compatibility, status and documentation | Independently useful with direct processors; does not require relay repair, durable packet transport, shared policy, or LI              |
| Tap and processor upstream parity | 4      | Applicable external upstream selection through the shared processor sender                                            | Uses the same selection policy, with its own lifecycle integration; production raw relay validation additionally requires phase 5       |
| Hierarchical forwarding           | 5      | Authenticated raw relay ingress and usable-route reporting                                                            | Requires general failover for handover tests; no durable packet guarantee yet                                                           |
| Shared filter policy              | 6      | Configurable common policy with versioned reconciliation                                                              | Optional alternative to each processor's own authoritative policy; hierarchy tests require phase 5                                      |
| Reliable raw-packet delivery      | 7–9    | Recoverable offline production, explicit receipt scope, replay and bounded deduplication                              | Optional; central receipts through relays require phase 5; packet correctness is not provided by the existing event spool automatically |
| LI specialization                 | 10     | Generation-aware authority and explicitly bounded disconnected LI behavior                                            | Optional, LI builds only; depends on applicable shared-policy and reliable-delivery contracts                                           |
| Integrated deployment validation  | 11     | Evidence for the profiles actually implemented and documented                                                         | Validate each milestone when released; later optional stages do not block the earlier core release                                      |

Do not silently expand this work into processor-state replication, simultaneous
multi-destination capture, automatic failback, central clustering,
or ADMF/MDF high availability. A common upstream may retain analysis state; direct
failover between independent processors does not transfer files or analysis state.

Tap parity is required by [cmd/tap/AGENTS.md](../../cmd/tap/AGENTS.md). Tap has no
hunter-to-local-processor gRPC connection: its applicable external destination list
must use `processor/upstream`, not an artificial local hunter connection. Phase 4
is an explicit additional integration, not an assumed consequence of changing the
hunter manager. The shared implementation should expose consistent upstream
configuration for `tap` and `process`.

## Required behavior and configurable contracts

### Endpoint selection

Use one normalized ordered endpoint configuration across flags, YAML, validation,
runtime setup, capture exclusions, and diagnostics. Preserve legacy scalar inputs.

| Setting                | Proposed interface                                                     | Initial behavior                                                                                                                                                      |
| ---------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Candidate list         | `--processors`, YAML `hunter.processors`                               | Ordered, one active destination; legacy `--processor/-P` and `hunter.processor_addr` remain supported                                                                 |
| Attempt budget         | `--processor-attempt-timeout`, `hunter.failover.attempt_timeout`       | Bounds dial/TLS/registration/readiness; start from the existing 10-second TCP dial timeout as a tunable compatibility-oriented default, not a performance requirement |
| Reconnect opportunity  | `--processor-reconnect-attempts`, `hunter.failover.reconnect_attempts` | One bounded attempt to reconnect to the current destination before advancing                                                                                          |
| Retry backoff          | `hunter.failover.retry_initial`, `retry_max`                           | Retain the existing 1-second initial and 60-second maximum backoff, with jitter applied after an unsuccessful sweep                                                   |
| Candidate TLS identity | Optional endpoint `tls_server_name` and transport settings             | Inherit existing credentials and verification policy; explicit endpoint overrides are validated                                                                       |

The proposed names are not existing options. Phase 0 verifies naming against the
current command/config conventions before phase 1 publishes them. Defaults above
are configurable behavior choices, not externally established latency gates.
Keep a single configured endpoint's existing retry behavior except where an
explicit new attempt budget bounds a previously unbounded operation.

Require positive attempt durations, nonnegative reconnect counts, and a positive
initial retry delay no greater than the maximum. A reconnect count of zero skips
the extra current-endpoint attempt; it does not disable cycling through candidates.
Reject duplicate endpoint definitions with conflicting transport identities.

At startup try candidates in order. On active-connection loss, spend the configured
current-endpoint retry budget, then advance and wrap. Keep a working backup active
when an earlier candidate recovers. Circuit breakers belong to endpoints; one open
breaker must not delay another eligible endpoint. If every candidate is cooling
down, wait cancellably until an eligible retry rather than spin.

Resolve scalar/list precedence across keys. An explicit CLI selector replaces
configured selectors; reject simultaneous scalar/list selectors at the same
effective priority. Do not merge unrelated lists or let a nonempty flag default
override YAML. Do not use `viper.IsSet` alone to infer explicit flag input. Preserve
existing environment behavior; explicitly bind any newly documented environment
variables instead of assuming a prefix or dot-to-underscore conversion exists.

### Delivery and filter profiles

Keep forwarding mode separate from delivery guarantees and policy ownership.
Existing event delivery profile settings retain their semantics.

| Choice                       | Proposed configuration                                                                    | Default / constraint                                                                                                                                                  |
| ---------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Payload mode                 | Existing `--forward-mode=packets` or `events`                                             | Preserve configured mode and existing explicit fallback rules                                                                                                         |
| Raw-packet delivery          | `hunter.packets.delivery_profile: best_effort` or `reliable`; `--packet-delivery-profile` | `best_effort` preserves existing loss boundaries; `reliable` is available only after phases 7–9                                                                       |
| Raw-packet receipt scope     | `hunter.packets.ack_scope: receiver` or `central`; `--packet-ack-scope`                   | Reliable mode defaults to durable receiver acceptance; `central` requires an explicit central destination identity and negotiated receipt support                     |
| Packet retention             | `hunter.packets.spool` settings                                                           | Explicit directory, bytes, age, per-record bound, protection, and `drop_oldest` or `drop_new` policy for reliable mode; no invented deployment-wide retention targets |
| Candidate filter policy      | `hunter.filter_policy.mode: processor` or `shared`                                        | `processor` applies each candidate's authoritative snapshot; `shared` requires configured authority/domain and phase 6 support                                        |
| Optional LI offline behavior | LI-specific policy configuration from phase 10                                            | No interception lease requirement for ordinary locally configured capture                                                                                             |

CLI values may accept hyphenated spellings using the project's existing enum
normalization pattern; store one canonical representation. Unsupported explicitly
requested guarantees must fail visibly during configuration or negotiation, not
silently fall back to weaker delivery. Do not advertise unfinished options.

`receiver` means the authenticated accepting processor durably owns further
delivery responsibility. Loss of that processor's storage can lose its sole copy.
`central` means the origin retains its copy until authenticated durable receipt
by the configured common upstream. It does not mean analysis, PCAP persistence,
or MDF delivery has completed. Receiver scope can be used without any upstream.

## Correctness invariants

- [x] The active processor list is usable in non-LI builds without ADMF/MDF,
      shared policy, reliable packets, or a common upstream.
- [x] At most one active sender/control generation exists per selected route;
      stale callbacks cannot stop or mutate its successor.
- [x] Candidate changes preserve origin identity, capture timestamps, interfaces,
      observation scope, and existing packet/event authorization boundaries.
- [x] A completed setup attempt does not leave a deadline attached to a healthy
      long-lived stream; failed or cancelled attempts release all owned resources.
- [x] Forwarding mode and pending event batches are not discarded or silently
      downgraded to make a candidate compatible.
- [x] Full filter snapshots distinguish authoritative empty state from failed
      synchronization; changed policy follows existing session-boundary rules.
- [x] Best-effort counters describe their actual send/drop boundaries. Durable
      profile counters and receipts distinguish enqueue, send, and durable acceptance.
- [x] Reliable raw batches retain immutable origin/session/sequence identities;
      deletion occurs only after valid receipt coverage or accounted retention loss.
- [x] Cumulative receipts never advance across unexplained sequence holes, and
      deduplication cannot merge conflicting payloads with the same identity.
- [x] All memory, storage, age, record-size, replay, and metadata limits remain
      enforced through disconnect, exhaustion, restart, and cleanup failure.
- [x] Relay trust does not weaken direct-hunter admission or turn arbitrary origin
      strings into authorized capture identities.
- [x] Idle expiry, finalized call boundaries, task generations, LI deactivation,
      cryptographic bounds, and configured limits remain intact where applicable.

## Phase 0 — Confirm interfaces and implementation boundaries

Primary files: [cmd/hunt/config.go](../../cmd/hunt/config.go),
[hunt.go](../../cmd/hunt/hunt.go),
[hunter.go](../../internal/pkg/hunter/hunter.go),
[connection/manager.go](../../internal/pkg/hunter/connection/manager.go),
[upstream/manager.go](../../internal/pkg/processor/upstream/manager.go).

- [x] Recheck the research findings against the current checkout and record only
      changed assumptions in this plan; do not reopen unrelated completed work.
- [x] Finalize a small shared endpoint/selection model, for example
      `internal/pkg/failover`, owning validated candidates, retry eligibility, and an
      injectable clock/jitter source. Keep transport lifecycle and policy application
      in their existing hunter/upstream managers.
- [x] Finalize the proposed config names, scalar/list precedence, duration/count
      validation, per-endpoint TLS inheritance, and error classifications.
- [x] Inventory every hunter protocol constructor and scalar-address requirement,
      exact CLI contract fixtures, capture exclusions, and diagnostics needing changes.
- [x] Write down the core readiness boundary for legacy peers. Lazy gRPC client
      construction or stream creation alone is not proof of successful packet ingress;
      track early stream failure without continually resetting the failed candidate's
      retry state. An idle healthy stream must not require dummy captured traffic.
- [x] Identify existing event snapshot/drain/session-rotation constraints. A new
      candidate with different policy must not deadlock pending replay against policy
      publication or reinterpret the old session under new policy.
- [x] Make negotiated mode publication transactional with successful setup.
      Explicit event-to-packet fallback commits for the producer lifetime only at the
      defined successful boundary; an unsuccessful candidate must not change global
      mode, start a producer, or publish readiness that survives the failed attempt.

**Exit evidence:** Concrete configuration and lifecycle contracts exist, with a
bounded list of affected call sites. No new wire protocol is required for direct
best-effort hunter failover.

## Phase 1 — Implement endpoint configuration and compatibility

- [x] Add the plural selector and failover settings to the hunt root command and
      centralized config builder, retaining empty defaults for selectors.
- [x] Normalize legacy scalar input into a one-element list, preserve order,
      reject blanks/malformed addresses, and reject or explicitly deduplicate repeated
      canonical endpoints without silently changing their priority.
- [x] Support simple address lists first; map optional structured YAML endpoint
      entries to the same internal model for TLS identity overrides. Reject conflicting
      credential settings before starting capture.
- [x] Replace scalar-only required-address checks consistently in generic, DNS,
      HTTP, TLS, email, VoIP, and other catalog-registered hunter commands.
- [x] Pass normalized endpoints to runtime and capture managers; keep legacy
      fields only as compatibility adapters, not a second source of selected state.
- [x] Test CLI-over-file precedence, same-level conflicts, legacy YAML/flags,
      explicit environment bindings if exposed, IPv6, duplicates, and duration bounds.
      Follow the command tests' Cobra/Viper state save/restore conventions.

**Exit evidence:** Old single-endpoint examples still resolve correctly, all
protocol commands accept the new selector, and invalid combinations fail before
capture. Update CLI contract defaults/binding fixtures deliberately.

## Phase 2 — Implement hunter connection handover

- [x] Integrate candidate selection into `connection.Manager`; give each attempt
      its own cancellation and endpoint-specific circuit-breaker/retry accounting.
- [x] Bound readiness/registration operations using attempt contexts. Ensure
      stream contexts survive a successful attempt budget and are cancelled with the
      owning connection generation, not the expired setup deadline.
- [x] Clean up data and management clients, streams, forwarding workers, and
      partial registrations on every failed attempt before selecting a successor.
- [x] Move registration, filters, packet/event transport, heartbeats, and control
      streams together. Reset stale peer-owned PAUSE/control state at the defined
      new-generation boundary while preserving producer-owned pending data.
- [x] Implement initial ordered attempts, current-peer reconnect budget, advancing,
      wraparound, cancellable unsuccessful-sweep backoff, and sticky success.
- [x] Keep permanent local configuration failures distinct from remote endpoint
      failures; report certificate, registration, capability, and policy rejection
      without weakening TLS or repeatedly claiming an unusable peer is active.
- [x] Preserve existing event replay, accepted-kind/profile negotiation, explicit
      packet-fallback policy, and policy-triggered producer rotation. A candidate
      incompatible with pending durable data is ineligible until resolved; never
      discard that data or silently change its producer identity.
- [x] Add deterministic local fake-processor tests for refused connections,
      blackholes, stalled registration, stream/control failure, stale callbacks,
      single-endpoint compatibility, all-candidates-down cancellation, and no failback.
- [x] Add packet/event integration cases for unchanged and changed candidate
      policy, pending replay, and incompatible peers. Use meaningful state/ownership
      assertions instead of arbitrary wall-clock performance gates.

**Exit evidence:** One active generation at a time, a failing first candidate
cannot indefinitely prevent reaching an eligible alternative, and existing event
and sender-ownership checks pass.

## Phase 3 — Finish general hunter integration and release documentation

- [x] Make self-traffic exclusions account for all configured data/control
      endpoints, mixed ports, IPv6, and DNS resolution changes as applicable. Avoid
      overly broad port exclusions that suppress intended monitored traffic.
- [x] Expose configured candidates, active endpoint, selection state, attempt
      reason, last successful connection, and failover count through existing logging
      and diagnostics surfaces. Keep cardinality bounded and redact credentials.
- [x] Distinguish connection availability from durable delivery. Preserve honest
      packet-drop reporting and document existing disconnected capture/disk-buffer
      limits; do not relabel current overflow as durable spooling.
- [x] Add non-LI integration coverage with two independent processors and no
      upstream, for raw packets and normalized events. State explicitly that their
      output files, analysis state, and deduplication stores are independent.
- [x] Update hunt usage, config examples, architecture notes, and affected manual
      sections and translations for the core milestone; run the manual checks below.
- [x] Format, validate, mark only verified tasks complete, and commit this
      milestone's code, documentation, and plan status as required by project policy.

**Exit evidence:** The general hunter feature is independently reviewable and
usable without later optional profiles. Do not claim tap upstream parity yet.

## Phase 4 — Add applicable tap and processor upstream parity

Primary integration points: [processor.go](../../internal/pkg/processor/processor.go),
[upstream/manager.go](../../internal/pkg/processor/upstream/manager.go),
[cmd/tap/runtime.go](../../cmd/tap/runtime.go), tap protocol config constructors,
and [cmd/process/process.go](../../cmd/process/process.go).

- [x] Add normalized upstream candidates and matching selection settings to the
      shared processor upstream manager, reusing the selection model rather than
      copying the hunter connection loop.
- [x] Expose consistent `tap.processors` and `processor.processors` selectors and
      matching flags while preserving their existing scalar processor/upstream aliases
      and command-specific configuration precedence.
- [x] Integrate full upstream registration, packet/event negotiation, sender,
      receiver, generation cleanup, and accepted-policy boundaries with selection.
- [x] Keep tap capture/local processing in process; an upstream outage must not
      invent a local gRPC dependency or unnecessarily interrupt local outputs.
- [x] Update every tap protocol config constructor, automatic self-traffic
      exclusion, stats/topology display, and scalar-upstream guard using the normalized
      configuration. Identify a configured upstream separately from an active one.
- [x] Test tap without upstream, tap switching upstreams, unchanged single upstream,
      local outputs during an upstream outage, and processor sender generation cleanup.
- [x] Update applicable docs/manual translations, run affected checks, format,
      update this plan based on evidence, and commit the parity milestone.

**Exit evidence:** Tap/process upstream selection parity is implemented without
breaking tap's local source architecture. Sender tests may use explicit test
services, but those tests do not establish production raw relay admission.
Production raw forwarding parity requires phase 5's real ingress tests; event-mode
parity is claimed only for its independently verified routing contract.

## Phase 5 — Establish authenticated raw relay ingress and route readiness

- [x] Reproduce the researched `RegisterProcessor` versus `AdmitPacketStream`
      mismatch using an integration test with one relay and multiple hunter origins.
      Keep the finding labelled source-based until that reproduction is established.
- [x] Add a versioned multiplexed relay ingress/open contract identifying the
      authenticated relay, authorized origin sessions, and negotiated packet profile.
      Prefer a dedicated relay RPC to loosening `StreamPackets` hunter admission.
- [x] Define authoritative relay-to-origin delegation, revocation, and session
      replacement. Bind authorization to authenticated peers and configured origin
      scope; topology visibility alone is not proof of delegation.
- [x] Preserve original hunter/capture metadata and separate relay-route metadata.
      Reject arbitrary origins, mixed contracts, unsupported versions, and packets
      whose observation provenance contradicts the authorized source.
- [x] Support the legitimate overlap during handover: old-relay backlog and a new
      active relay can carry the same producer identity. Do not invalidate eligible
      historical custody merely because topology reports a new active route.
- [x] Report local connection, common-upstream identity/readiness, policy readiness,
      queue/spool capacity and age, and receipt progress separately. An absent upstream
      generation must not look like a healthy empty forwarding queue.
- [x] Keep SLOW/PAUSE overload distinct from route failure; avoid making every
      hunter switch routes when the shared central processor is overloaded.
- [x] Test real hunter → relay → central packets, two origins on one relay, two
      relays sharing central, forged delegation, old peers, and upstream interruption.
- [x] Publish capability/upgrade order and truthful best-effort limitations, update
      relevant translations, validate, format, update the plan, and commit.

**Exit evidence:** Hierarchical raw forwarding works through authenticated relay
contracts without weakening direct-hunter checks. No durable receipt is implied.

## Phase 6 — Implement optional shared filter policy

- [x] Implement `processor` policy mode first using existing authoritative candidate
      snapshots and explicit policy/session transitions. Different policies are allowed
      when configured, not silently represented as equivalent.
- [x] Add `shared` mode with a configured authority/domain, monotonically versioned
      full snapshots, explicit empty state and deletions, and reconciled incremental
      updates. Use the established filter store/canonical representation.
- [x] Distribute applicable desired policy to every eligible candidate, including
      backups with no current hunter registration. Persist enough authority/version
      information to reject stale restoration after relay restart.
- [x] Authenticate the policy owner through the selected trust model. A matching
      content hash proves equality, not authority; reject unauthorized owners and
      rollback. Keep relay-local operator filters separate from centrally owned data.
- [x] Publish readiness only after the required snapshot is installed. Apply
      changes atomically across effective BPF/application policy, and retain the
      existing producer drain/rotation contract where policy changes require it.
- [x] Define configured startup/offline behavior: local policy, allowed cached
      remote snapshot, or waiting for remote policy. Do not require interception leases
      for ordinary capture. Already batched data retains its original policy provenance.
- [x] Test deletions, empty snapshots, missed updates, stale backups, cold backups,
      concurrent revisions, policy fault recovery, and reconnect during event draining.
- [x] Document configuration and migration, validate, format, mark verified work,
      and commit without claiming the later LI offline-authorization profile exists.

**Exit evidence:** Deployments can choose independent processor policy or common
managed policy without silently broadening capture or stranding event sessions.

## Phase 7 — Define reliable raw-packet identity and lifetime-independent storage

- [x] Add versioned raw origin/session/batch identity independent of connection
      generations, with explicit capture/policy session recovery and rotation rules.
      Old packet fields remain readable but do not negotiate stronger guarantees.
- [x] Bind reliable records to a configured logical destination/domain. For
      independent receivers, document possible cross-processor duplicate processing;
      local deduplication is not shared global state. Central scope requires one
      explicit trusted central identity through every candidate route.
- [x] Define durable append, receipt-commit, loss-range, session-retirement, and
      recovery records. Bound per-record sizes and fragmented loss metadata before
      allocation; enforce integrity and transport collection limits.
- [x] Implement a recoverable raw spool with explicit directory ownership, file
      permissions, storage protection/key policy, crash-safe publication, and retryable
      cleanup. Do not recover the existing destructive packet overflow as if it had
      this contract, or delete it silently during migration.
- [x] Separate capture/filter/batch/spool production from per-connection sending
      for reliable packet mode. Preserve shared protocol processing rather than
      introducing a second hunter-only analyzer loop.
- [x] Continue eligible offline production within configured bytes/age/memory
      limits. Implement `drop_oldest` and `drop_new` with exact, bounded durable loss
      coverage, including records already staged by a sender when eviction occurs.
- [x] Preserve original capture timestamps, source interfaces, direct/inherited
      evidence separation, and configured capture restrictions through raw records.
- [x] Test restart and I/O faults at publication boundaries, exhaustion, oversized
      records, corruption, queue loss accounting, and interrupted policy rotation.

**Exit evidence:** Offline eligible raw production and recoverable retention work;
records are not retired based merely on transport `Send`. Do not publish reliable
delivery as usable until phase 8 establishes its acceptance boundary.

## Phase 8 — Implement receiver/central durable receipts and replay

- [x] Add negotiated durable receiver acceptance with atomic or recoverably
      consistent recording of payload, deduplication state, and receipt coverage before
      ACK. Document what durable ingestion does and does not guarantee about outputs.
- [x] Track durable acceptance separately from downstream processing completion.
      Restart must drain accepted but unfinished work even when duplicate ingress is
      suppressed. Retire receiver payload only after its declared processing/custody
      boundary, not merely because an origin receipt has been emitted.
- [x] Implement central receipt scope: relays forward or allow querying central
      committed coverage through the new active path. Bind receipts to authority/key,
      destination/domain, origin/session, and sequence coverage; verify origin-side
      central authenticity instead of trusting a relay's assertion of receipt scope.
- [x] Make relay responsibility explicit: durable receiver custody requires
      retained upstream retry; central scope can tolerate lossy transit because the
      origin retains unconfirmed records. Local transit receipts never masquerade as
      central receipts or retire an origin copy in central mode.
- [x] Replay pending records with immutable identities and content; reject
      conflicting identity reuse. Deduplicate before duplicate-sensitive analysis and
      output dispatch. Recover receipt and deduplication state consistently.
- [x] Never acknowledge past unexplained holes. Support bounded selective coverage
      or contiguous coverage plus authenticated loss ranges, including loss-only
      progress and lost-return-ACK recovery.
- [x] Bound deduplication/session history; retire sessions through an explicit
      protocol and reject replay outside retained guarantees rather than treating it
      as fresh traffic. Apply the same discipline to restart and destination changes.
- [x] Pace replay with flow control and bounded working sets. Define live/backlog
      fairness without unbounded reorder buffers or inventing throughput targets.
- [ ] Test each crash boundary: before receipt, receiver commit before ACK, relay
      loss before forwarding, central commit before return receipt, duplicate delivery
      via two relays, generation teardown, and receiver restart.
- [x] Verify explicit reliable settings reject incapable peers without deleting
      pending records or silently falling back to best effort or event mode.

**Exit evidence:** Each advertised receipt scope survives its documented failure
model. Central ingestion deduplication is not an exactly-once claim for arbitrary
analysis/output side effects, independent processors, or MDF delivery.

## Phase 9 — Integrate late data, bounded analysis, and auxiliary metadata

- [x] Preserve observation scope across route changes, add capture epoch where
      required by the raw contract, and keep relay route outside canonical flow keys.
- [x] Define default late-data behavior using current bounded live analysis;
      surface late/gap outcomes instead of automatically extending idle timeouts.
      Any separately supported offline/backfill mode must have explicit resource limits
      and output semantics, not resurrect finalized live state.
- [ ] Test TCP and VoIP continuity across relay changes, overlapping private address
      spaces from different hunters, old-relay backlog after newer traffic, and
      expiry/finalization before replay. Do not promise shared state for independent
      processors or continuity through arbitrary blackout duration.
- [ ] If decryption is enabled, verify or complete production TLS-key attachment
      and acknowledged retention/retransmission; the existing helper alone does not
      establish that path. Keep secrets protected and immutable during fan-out/replay.
- [x] Expose raw spool depth/bytes/age, receipt scope/progress, replayed/duplicate/
      dropped/late counts, policy version and route status with bounded labels.
- [x] Update reliable-profile docs, upgrade/recovery procedures, and every affected
      manual translation. Validate phases 7–9 together before advertising the profile,
      format, mark verified tasks, and commit the completed reliable milestone.

**Exit evidence:** Configured durable guarantees and analysis limits agree with
observable behavior; transport retention and consumer delivery age remain distinct.

## Phase 10 — Add optional LI-specific integration

- [x] Keep LI-specific policy interpretation and checks behind existing build-tag
      boundaries; generic hunters/relays carry necessary provenance without becoming
      X1 task managers or requiring ADMF/MDF configuration.
- [x] Preserve central authority incarnation, activation generation, filter revision,
      source scope and validity in authenticated capture-policy provenance. Ordinary
      reused filter IDs alone must not authorize delayed traffic under a new task.
- [x] Define a deployment-configured disconnected LI policy consistent with actual
      task semantics, including `ImplicitDeactivationAllowed`. A proposed offline lease
      is a new contract, not a claim that every existing task end time deactivates.
- [x] If bounded offline interception is enabled, enforce authenticated validity,
      expiry, clock uncertainty/rollback, and restart recovery locally. Loss of contact
      or reboot cannot renew authority. State explicitly that an absent control path
      cannot deliver immediate revocation.
- [x] Preserve current central activity/expiry/generation admission, deactivation
      queue cancellation, persistent replay cutoffs, destination generations, finalized
      call boundaries, and X3 age measured from central admission. Do not enable
      historical delivery after expiry merely because capture occurred earlier.
- [x] Extend trusted relay origin delegation to applicable RADIUS provenance;
      keep current direct-peer suppression until the delegated contract is verified.
      Preserve authoritative call ownership and direct/inherited RTP evidence checks.
- [ ] Test stale policy, task modification/reactivation, long-disconnected backup,
      clock rollback, revoked source, delayed X3, and expired destination. Separately
      test central/MDF outage without calling transport receipt MDF delivery.
- [x] Document LI-only options and limits, update translations, run LI/non-LI
      partition checks, format, update plan status, and commit the optional milestone.

**Exit evidence:** LI specialization strengthens the generic transport's consumer
contract without becoming a dependency of ordinary capture or failover.

## Phase 11 — Validation, documentation, and completion evidence

Run applicable checks at each milestone; do not repeatedly run every suite without
a new change or unresolved failure. Use deterministic fake services for lifecycle
tests and real local gRPC/TLS integration for boundary behavior. If sandbox limits
prevent required tests, request the necessary escalation. Stop and report unrelated
blocking issues under project instructions instead of repairing them implicitly.

- [x] Run focused config, connection, forwarding, filtering, and existing event
      replay tests for phases 1–3, including targeted race tests for generation changes.
- [x] Run upstream/tap tests for phase 4; run real raw relay and origin-trust tests
      for phase 5, including multiple sources and alternative routes.
- [x] Run snapshot/policy-boundary tests for phase 6, storage/recovery/receipt fault
      tests for phases 7–9, and applicable LI admission/replay tests for phase 10.
- [x] Exercise the current project's required `make test` and `make vet` checks at
      the relevant release boundary, plus `make build-matrix` when changed runtime,
      generated contracts, or build-tag surfaces affect role partitions.
- [x] Regenerate protobuf code using the repository's established generation
      workflow when contracts change; preserve field compatibility and capability
      negotiation. Use latest stable tooling unless compatibility requires otherwise;
      avoid unrelated dependency upgrades and record applicable CI notices.
- [x] Update usage/config references, architecture notes, protocol-specific command
      examples, and [research](../research/hunter-processor-failover.md) to distinguish
      implemented guarantees from remaining optional work.
- [x] For affected manual content, update every language in
      [languages.json](../manual/languages.json), resolve affected fuzzy entries, and
      run `make manual-check` and `make manual` before declaring that update complete.
- [x] Format Go/protobuf/documentation changes before staging. Clean task-owned
      `/tmp` caches, inspect the final diff, and commit code and verified plan updates
      for each completed implementation milestone as required by project policy.
- [x] Record test commands/results, implemented option defaults, capability/upgrade
      requirements, remaining unchecked optional stages, and any material limitations.

Focused commands to adapt to the changed packages include:

```bash
go test -tags all ./cmd/hunt ./internal/pkg/hunter/...
go test -race -tags all ./internal/pkg/hunter/connection ./internal/pkg/hunter/forwarding
go test -tags hunter ./cmd/hunt ./internal/pkg/hunter/...
go test -tags all ./cmd/tap ./cmd/process ./internal/pkg/processor/upstream/...
go test -tags tap ./cmd/tap
```

No latency, throughput, outage duration, soak, CPU, or RSS acceptance target is
introduced by this plan. Record exploratory measurements if useful, but do not
turn chosen defaults or benchmark observations into new implementation gates.
Correctness, authentication, existing safety limits, and each explicitly selected
delivery contract must still be verified.

## Completion criteria

- [x] Core failover works with old single-address configuration and ordered lists,
      independent processors, non-LI builds, and both existing forwarding modes.
- [x] Tap parity is either completed and verified at its milestone or clearly
      reported as outstanding; production raw parity includes phase 5 ingress evidence,
      and the hunter-only release is not labelled full parity.
- [x] Optional profiles are enabled only after their corresponding contracts and
      failure scenarios pass; unimplemented options are not advertised as functional.
- [x] Documentation describes finite retention, independent analysis state,
      authenticated receipt boundaries, and applicable policy restrictions accurately.
- [x] Checked tasks have evidence and corresponding implementation commits;
      unimplemented optional work remains unchecked rather than being called complete.

## Historical implementation checkpoint — 2026-10-15

Work stopped under the project's unexpected-issues instruction after the full
host test suite found missing mandatory detector fixtures in `testdata/pcaps`:
`http.pcap`, `tls.pcap`, `dns.pcap`, and `rtp.pcap`. The failure is in the unchanged
`TestComprehensivePcapDetection` test, before it can exercise protocol detection.
These fixture files are unrelated to processor failover and were not synthesized,
substituted, or made optional. Restore the authoritative fixtures or explicitly
scope their handling before continuing implementation.

Preserved work includes shared candidate/configuration resolution, hunter and
upstream handover code, scoped hunter capture exclusions, authenticated raw relay
v1 ingress/sending, capture-session metadata projection, and core usage/manual
updates with German and Catalan translations. This is work in progress, not a
claim that phases 0–5 or the whole plan are complete. Shared policy and durable
packet profile designs have not been implemented; LI integration remains pending.

Verification before stopping:

- Targeted failover/configuration, capture-exclusion, upstream selection, relay
  ingress, and local-output-during-upstream-outage checks passed. The applicable
  upstream race and LI command-partition checks also passed.
- `make vet` passed on the host, including the LI partition.
- `make manual-check` and `make manual` passed for every configured language. The
  installed mdBook/gettext version warning did not prevent their successful builds.
- `make test` failed on the unrelated missing detector fixtures and also exposed
  an unfinished **related** connection-test regression: a new handover test factory
  leaves the forwarding batch timeout zero, causing `time.NewTicker(0)` to panic.
  Resolve and rerun that regression when implementation resumes; it is not covered
  by earlier targeted passes. The full test target did not reach its separate LI
  package invocation after the first invocation failed.
- Sandbox filesystem ownership remapping initially caused existing secure-store
  tests to reject `/` and `/tmp` (UID 65534). Authorized host test runs avoided that
  environmental restriction without changing the secure-store checks.

Only the independently verified phase-1 configuration tasks are checked above.
Later tasks and completion criteria remain unchecked. The branch must not be
presented as a finished or fully validated implementation.

## Implementation and validation checkpoint — 2026-10-17

User-authorized continuation supersedes the historical stop above. The connection
regression was fixed. General ordered selection, tap/process upstream parity,
authenticated raw relays, signed shared policy, persistent raw origin storage,
signed receiver/central receipts, replay/deduplication, diagnostics, and the
restricted optional LI capture-authority profile are implemented. See
[the operator guide](../PROCESSOR_FAILOVER.md) for the supported configuration.

Verified evidence:

- [x] Full race suites passed for failover, filterpolicy, packetspool, packetreceipt,
      hunter and processor subpackages, affected command packages, statusclient,
      and pipeline adapters (`go test -race -tags all` with those package paths).
- [x] `go test -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor
./internal/pkg/hunter ./cmd/hunt ./cmd/tap ./cmd/process ./cmd/set` passed.
- [x] `go test -tags all ./... -skip '^TestComprehensivePcapDetection$'` passed.
      This is not a passing unmodified `make test`: the authoritative detector
      fixtures listed in the historical checkpoint are still absent. The user
      authorized continuation without inventing substitute captures.
- [x] `make vet`, `make build-matrix`, and `make -C api/proto` passed. The build
      matrix covers supported non-CUDA roles; CUDA needs its configured builder.
- [x] `make manual-check` and `make manual` passed for English, Catalan, and German;
      both translation catalogs cover 5802/5802 messages. The installed mdBook
      helper version warning did not prevent any edition from building.
- [x] Closure review found and fixed two concrete defects: a blocked reliable
      network Send now cancels its RPC within the configured send budget; new raw
      ingress and policy-read RPCs now explicitly permit the hunter API-key role,
      while policy mutation retains admin requirements. Focused race regressions
      passed, including retained origin data after a blocked send.

Follow-up status distinguishes verified additions from remaining limits:

- [x] Add one deployment-level test switching an actual hunter between two
      independent processors in both raw and normalized-event modes. Existing
      connection tests use real local gRPC fake services; real TLS relay tests
      separately cover two origins, alternative relays, and common central custody.
- [x] Extend the composed crash-boundary scenario matrix beyond the existing
      spool/custody publication-fault, restart, duplicate-route, and lost-receipt
      tests. Output effects remain at least once after a crash between dispatch and
      completion checkpoint; no exactly-once PCAP/MDF guarantee is advertised.
- [x] Add TCP/VoIP handover and long-blackout semantic integration scenarios.
      Current source/epoch isolation and existing bounded protocol analyzers remain
      in force; replay does not extend idle timeouts or revive finalized state.
- [ ] Complete matched-session TLS-key attachment and acknowledged retransmission.
      The existing HTTP keylog/decryptor helpers have no production attachment
      provider. Reliable raw plus HTTP keylog options are rejected. Ordinary TLS
      packet bytes can still be retained and forwarded unchanged.
- [ ] Extend optional LI deployment-level outage/renewal validation. LI-owned
      hunter capture currently supports synchronous raw filtering only and requires
      reliable encrypted raw storage, independently encrypted policy state, and
      signed finite authority. VoIP/custom-buffer LI hunter mode is rejected.

Reliable `receiver` scope supports a terminal receiver only; a forwarding relay
must use `central` scope. This explicit rejection avoids claiming retained relay
upstream custody that is not implemented. Retention/history capacities are finite;
full history requires operator-managed retirement/reprovisioning. Dropped raw
status counts durable lost **batches** (including confirmed gaps), while replay,
duplicate, and late observations count packets for the current runtime.

The core release is independently complete under the plan's milestone boundaries.
The whole optional scenario matrix and auxiliary TLS-key path are not complete.
The bounded closure review finished with no remaining material findings in the
implemented scope after the two repairs above. The release decision is
`CLOSED_WITH_DEFERRALS` for the documented profiles and explicitly listed external
fixture/optional-work limits; it is not closure of every optional plan task.

## Integration follow-up checkpoint — 2026-10-25

The [operational visibility implementation plan](operational-visibility-and-offline-investigation.md)
adds actual-hunter failover coverage with two independent production processors
for packet and normalized-event modes. The test validates filter and ingress
readiness, sticky backup selection after primary recovery, producer provenance,
independent processor analysis, edge-owned event continuity, and raw PCAP output.
Sender restart recovery and the new receiver commit/lost-receipt and
output-before-processing-checkpoint scenarios pass focused normal and race checks.
The latter explicitly demonstrates the documented at-least-once output boundary.

This completes the two-independent-processors checklist items above. The full
historical crash matrix and auxiliary TLS-key delivery remain outside that claim;
protocol handover, origin/epoch isolation and expiry/finalization scenarios now
pass repeated race checks. Real mTLS relay tests verify TCP/SIP/RTP continuity at
a common upstream and independent analysis at separate processors. Replay after
configured expiry/finalization cannot restore discarded TCP prefixes or mutate
finalized aggregate/PCAP state. The tests exposed and fixed a missing capture
epoch in the TCP namespace digest. The umbrella W1 scope is closed; the broad
original phase-8/phase-9 scenario lists remain unchecked where their entire
historical combinations were not exercised.
