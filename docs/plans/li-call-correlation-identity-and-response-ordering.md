# LI call correlation: identity normalization and response ordering

**Status:** implemented, verified and committed; local implementation closed.

**Scope:** optional LI call-leg correlation in processor and tap, including
configuration, bounded response-first handling, diagnostics and documentation.

## Objective

Allow explicitly configured telephone identities to correlate across SIP number
rewrites, and allow a briefly reordered initial INVITE to supply evidence before
the first Correlation ID is reserved. Preserve conservative handling of ambiguous
sessions, task authorization, immutable decisions and durable publication.

This plan is standalone and contains only generic protocol scenarios. Operational
captures, identities, traffic counts, topology, deployment-specific rewrite rules
and private artifact locations are excluded. Tests and examples must use synthetic
identities and reserved example domains and addresses.

## Existing behavior and boundaries

`correlationIdentity` preserves the extracted user/number and folds only host
case. The shared `extractHeaderURI` helper discards URI parameters, so it cannot
by itself implement telephone comparison that preserves local-number context
and extensions. R1 uses called identity and address/setup evidence; R2 uses the
calling/called pair and runs only when there is no eligible address candidate.
Reference grouping windows in a diagnostic replay are not matching windows.

A response-first observation currently reserves a standalone decision. A later
INVITE retains that decision and cannot retroactively turn it into an indexed
candidate. `ResolveAsync` already defers packets for persistence, but that state
begins after an ID has been selected. Response reordering requires a separate
state before reservation.

The existing [call-leg correlation plan](li-call-leg-correlation.md) and
[recovery hardening plan](li-correlation-and-replay-recovery-hardening.md) describe
established behavior. This work adds explicit normalization and optional
pre-reservation waiting; it does not reopen their completed implementation.

## Invariants and scope limits

- [x] Preserve current identity comparison when normalization is not configured.
  Keep correlation methods independently opt-in. Normalization or pending-state
  configuration alone must not enable a matching method.
- [x] Preserve H/P/S precedence, trusted-header conflict rejection, task-context
  intersections, startup blind periods, logical expiry and terminal grace.
- [x] Never use normalized identities or group membership as evidence of task
  authorization, target matching, media ownership or inherited identity.
- [x] Keep source signaling, media payloads, direction, destinations and matched
  filters unchanged. Final CIN interpretation and content deduplication remain
  outside this change; shared IDs do not themselves suppress duplicate content.
- [x] Keep a Correlation ID immutable once reserved, including after failed
  dispatch. Preserve persistence outcomes, encrypted-store bounds, journal
  replay bytes and sequencing under the selected correlation context.
- [x] Preserve configured resource limits and retained decisions. Bound all new
  profiles, rules, pending entries and retained snapshots without evicting
  existing decisions to make room.
- [x] Keep capture time for matching evidence separate from the local elapsed
  time used to bound response waiting. Do not automatically widen matching
  windows or tune resource caps to improve a replay result.

No latency, throughput, memory, CPU or grouping-percentage acceptance target is
introduced. Exploratory replay measurements inform diagnosis; they do not create
performance gates or authorize unrelated optimization work.

## Implementation map

| Responsibility | Existing entry points | Likely additions |
| --- | --- | --- |
| Config and validation | `internal/pkg/li/call_correlation_config.go`; `cmd/process/flags_li.go`; `cmd/tap/flags_li.go` | Typed normalization profiles and response-wait configuration |
| URI comparison keys | `internal/pkg/li/call_correlation.go`; shared extraction in `direction.go` | Correlation-specific URI parser/key builder in `call_correlation_identity.go`; profile validation in `call_correlation_identity_config.go` |
| Pre-reservation waiting | `ResolveAsync`, `ResolveContext`, `resolveLocked`, maintenance and close in `call_correlation.go` | Pending-dialog state and deadline/release logic in `call_correlation_pending.go` |
| Snapshot admission and delivery | `internal/pkg/processor/processor_li.go`; `processor_li_correlation.go`; processor lifecycle | Integration with existing owned snapshots and delivery revalidation |
| Aggregate diagnostics | `internal/pkg/processor/processor_li_correlation_stats.go`; status client and protobuf mapping | Pending outcomes and useful bounded reason counters |
| Operator documentation | `docs/LI_INTEGRATION.md`; manual correlation chapter and config reference | Generic configuration examples, compatibility and limitations |

Use responsibility-based filenames. Keep implementation under the existing LI
build tags and shared configuration usable in non-LI builds. Prefer existing
parsers and standard-library facilities where they meet the comparison contract;
if a new dependency is necessary, use its latest stable compatible release.

## Implemented configuration and behavior

Both role namespaces use the same final keys:

| Key | Default | Meaning |
| --- | --- | --- |
| `identity_profiles` | `[]` | Explicitly scoped telephone normalization; empty preserves legacy comparison |
| `response_wait` | `false` | Enable waiting before the first Correlation ID reservation |
| `response_wait_window` | `5ms` | Configured local elapsed wait; matching still uses capture timestamps |
| `max_pending_dialogs` | `1000` | Bound response-origin FIFO owners |
| `max_pending_packets` | `10000` | Bound retained response-origin snapshots |
| `max_pending_bytes` | `16777216` | Bound retained metadata and snapshot bytes |

Profiles contain `name`, `namespace`, `sip_hosts`, `phone_contexts`, `global_tel`,
`allow_numeric_sip`, `allow_bare_global`, `international_prefixes` and
`rewrite_rules`. Each rewrite has `pattern` and `replacement`. Switches default
to false and lists to empty. No new dependency was needed. Zero wait/limit fields
normalize documented defaults; negative or oversized limits and invalid profiles
fail validation. These settings alone do not enable any matching method.

Pending accounting composes with existing candidate, record and deferred-byte
bounds. An unadmitted new dialog falls back to ordinary standalone selection.
Overflow of an existing FIFO rejects the current snapshot explicitly and releases
previously admitted work conservatively. Cancellation and close discard ineligible
work. Finalization before selection prevents adoption and preserves authorized
signaling with a standalone decision. An already selected ID stays immutable.

The response-origin FIFO remains accounted through persistence and draining;
retention pinning does not extend candidate evidence lifetime or terminal grace.
Aggregate `response_wait` outcomes and pending dialog/packet/byte gauges are
available in status protobuf/JSON. Snapshot lifecycle rejection has one existing
X3 suppression-counter owner.

## 1. Establish synthetic contracts and configuration

- [x] Add reusable synthetic SIP fixtures with explicit session labels, covering
  two-leg and longer chains, unrelated concurrent calls, redials, forks,
  retransmissions, re-INVITEs, missing requests and response-first arrival.
  Derive expected membership from fixture construction, not number/time grouping.
- [x] Exercise fixtures through the production SIP parser as well as the
  correlator. Include UDP fragmentation and supported TCP reassembly paths where
  relevant; distinguish capture timestamps from processing arrival order.
- [x] Specify typed, named normalization profiles under both
  `processor.li.correlation` and `tap.li.correlation`. Each profile must define
  its applicable SIP hosts/telephone contexts, canonical namespace, permitted
  number-format interpretations and anchored rewrite rules. No profile means
  existing exact comparison. Ambiguous profile selection must not guess.
- [x] Specify a separate response-wait enable switch, positive configured wait
  window and explicit pending dialog/packet/byte limits. Keep it disabled by
  default. Document how these bounds compose with existing deferred persistence
  accounting, `max_candidates`, `max_records` and snapshot limits.
- [x] Define default and invalid-value semantics before extending `Normalized`,
  `Enabled` and `Validate`; explicit disablement must survive normalization.
  Record final field names in this plan when implemented rather than treating
  provisional names as an existing public API.
- [x] Extend processor/tap YAML and environment decoding symmetrically, including
  structured-profile decoding, explicit empty overrides and contextual errors.
  Add parity, invalid-config and non-LI configuration tests.

## 2. Build context-aware correlation identities

- [x] Parse SIP/SIPS and `tel:` identities into typed comparison inputs without
  changing the shared authorization/direction extractors. Preserve scheme and
  user semantics relevant to the selected comparison mode; do not turn arbitrary
  usernames into telephone numbers merely because they contain digits.
- [x] Preserve exact non-telephone user/domain identities and user case. For
  telephone comparison, distinguish global numbers from local numbers and retain
  `phone-context`, extension, subaddress and other identity-bearing parameters.
  Follow the applicable URI comparison rules in RFC 3261 and RFC 3966.
- [x] Remove telephone visual separators where the URI rules permit. Interpret
  bare digits or international dial prefixes as global numbers only through an
  explicit profile. Host-independent comparison must stay inside that profile's
  canonical namespace; do not collapse local extensions or tenants implicitly.
- [x] Apply configured routing rewrites only in their declared profile. Compile
  anchored Go-compatible patterns at startup, validate replacements, bound rule
  counts and input/output lengths, and reject invalid configuration. Do not use
  lookahead or add a richer regex engine solely to support it.
- [x] Define deterministic, idempotent canonicalization: avoid implicit repeated
  stripping or cascading rewrites. Conflicting applicable rewrites must produce
  no usable telephone key rather than selecting a favorable match. Malformed,
  empty or out-of-bound outputs must not enter an index.
- [x] Build namespace-qualified called and calling/called index keys. Apply them
  to R1/R2 only, retaining all existing address, setup, time-window, task and
  stronger-evidence checks. Do not change retained IDs or restore behavior when
  configuration differs after restart.
- [x] Test equivalent configured forms and distinct domains, local contexts,
  extensions, usernames, country codes, tenants and prefixes. Include malformed
  input, overlapping profiles, conflicting rewrites and normalization collisions.
  Keep generic last-N-digit and suffix matching out of the implementation.

## 3. Add bounded response-first state before reservation

- [x] Represent waiting separately from `correlationRecord`, `record.ready` and
  pending persistence groups. An eligible response for an unseen Call-ID may
  retain immutable snapshots without reserving an ID. Keep transaction identity
  explicit so forks or unrelated transactions do not supply request evidence.
- [x] Require an observed initial INVITE before promoting a waiting dialog to
  matching. Preserve valid CSeq zero handling and initial-request eligibility.
  Responses to re-INVITEs, unknown transactions and ambiguous SDP offer/answer
  roles must not acquire guessed evidence from response direction or tags.
- [x] On the corresponding initial INVITE, resolve once using that evidence,
  then hand buffered packets through the existing persistence and delivery path
  with one selected ID. Preserve same-dialog admission order, avoid encoding the
  INVITE twice and ensure concurrent packets cannot bypass the buffered FIFO.
- [x] Route subsequent signaling and associated X3 for a waiting dialog through
  the same first-decision boundary. A truly X3-first dialog without a waiting
  response keeps its existing standalone behavior. Do not inherit a Call-ID or
  task identity solely to place unrelated media in the waiting queue.
- [x] Define all release outcomes. Timeout or pressure before sufficient request
  evidence conservatively reserves standalone once and releases admitted
  snapshots in order. Later requests retain that decision. Cancellation,
  invalidated task/call lifetimes and shutdown discard ineligible snapshots with
  explicit accounting. Never reinterpret a persistence-uncertain adopted ID as
  an undecided response wait.
- [x] Serialize INVITE, deadline, pressure, cancellation, finalization and close
  races so each snapshot is delivered or discarded at most once. Account for
  metadata, packet count and bytes, including bursts for one dialog. Do not
  invoke callbacks, storage or admission APIs under the correlator mutex.
- [x] Enforce logical deadlines on lookup and schedule releases independently of
  storage progress. Do not rely solely on a maintenance tick that can be delayed
  or return early when the persistence owner is busy. Use an injectable clock
  and explicit test synchronization rather than elapsed-time acceptance targets.
- [x] Reuse `snapshotLICorrelationPacket` and `deliverLICorrelationSnapshot` to
  retain original admission time, task generation/state incarnation, call
  generation/incarnation, provenance and dedup ownership. Revalidate each packet
  at release; never authorize it using the union of waiting packets' tasks.
- [x] Preserve processor/tap shutdown fencing. Current processor cancellation
  precedes downstream teardown, so cancel/discard uncommitted waiting snapshots
  and prevent callbacks after close. Do not promise publication after context
  cancellation or bypass admission checks to force a shutdown drain.
- [x] Define synchronous `Resolve`/`ResolveContext` behavior consistently with
  `ResolveAsync`, including context cancellation and same-Call-ID concurrency.
  Ensure synchronous waiting cannot block unrelated packet processing or create
  a second decision alongside the async path.

## 4. Characterize weak-rule collisions and residual splits

- [x] Add explicit synthetic cases for concurrent calls to the same called
  number through a shared signaling node, including a single eligible prior
  group. Multiple-candidate rejection alone does not make R1 session-unique.
- [x] Cover identical calling/called pairs in concurrent calls and rapid redials,
  plus legitimate caller rewrites across a chain. An exact canonical pair is
  useful evidence, not a unique session identifier.
- [x] Cover rewritten-address matching with different party identities and
  unrelated parallel dialogs. Report the exact identity profile and enabled
  rules for every result; do not combine results across configurations.
- [x] Distinguish demonstrated contradictory evidence from missing evidence.
  Where observable evidence supports a bounded conservative collision veto,
  implement it with positive-chain and negative-session regressions. Preserve
  stronger H/P/S evidence handling and each weak method's opt-in semantics.
- [x] If otherwise indistinguishable sessions remain possible, document that
  limitation and the affected rule's operational suitability. Do not claim
  normalization solves it, guess a winner by recency, or expand this work into
  an unsupported promise of perfect session reconstruction.
- [x] Diagnose residual synthetic replay splits by transaction and reason:
  identity mismatch, timing window, eligible address candidates suppressing R2,
  setup overlap, task context, ambiguity, expiry or configured capacity. Record
  effective configuration instead of assuming code defaults. Preserve current
  R2 fallback and timing policy unless a separate correctness case justifies a
  specific, tested change; do not widen windows to fit reference labels.

## 5. Integrate diagnostics, persistence and delivery verification

- [x] Expose bounded aggregate outcomes for waiting, request-backed resolution,
  timeout, pressure, cancellation and shutdown, plus current pending entries,
  packets and bytes. Assign each counter one increment owner. Do not add URI,
  telephone number, Call-ID or profile-pattern values to metric labels or routine
  warnings. Avoid unnecessary protobuf changes; regenerate if the status contract
  needs new fields.
- [x] Ensure normalization failure and residual matching reasons can be diagnosed
  through synthetic tests or controlled tooling without exporting operational
  identities. Separate fully/partially grouped sessions, expected transitions,
  cross-session merges and unknown classifications; grouping coverage is not
  verified correlation accuracy.
- [x] Extend blocked-store, deadline, persistence-outcome and snapshot-ownership
  tests. Prove unrelated retained and standalone calls progress while another
  call waits for its request or storage, using explicit barriers.
- [x] Exercise committed, not-committed and uncertain persistence outcomes after
  a response wait. Preserve group task intersections, write serialization,
  reconciliation, selected IDs and the existing publication protocol. Pending
  packets must not enter a durable queue before their decision permits it.
- [x] Verify X2/X3 sequencing, immutable multi-destination bytes, partial fan-out,
  journal admission/replay and task revalidation through actual processor paths.
  Include task modification/deactivation/expiry, call finalization, Call-ID reuse,
  duplicate releases, close races and retained decisions after restart.
- [x] Keep the undecided response queue volatile; do not persist raw packets or
  canonical identity indexes as part of the correlation store. Document loss of
  undecided snapshots on process failure. Any store-format change must receive
  explicit migration coverage rather than silently reinterpreting old records.

## 6. Document, validate and complete

- [x] Update `docs/LI_INTEGRATION.md`, applicable configuration examples and the
  manual's correlation chapter/config reference with final keys, opt-in defaults,
  profile scope, failure outcomes, configured limits and collision limitations.
  Clearly distinguish waiting before reservation from storage waiting after it.
- [x] Translate every changed manual passage in all languages configured in
  `docs/manual/languages.json`, following `docs/manual/README.md`. Review affected
  fuzzy entries; preserve code examples, link targets and heading IDs.
- [x] Format changed files and run focused LI package, processor, configuration,
  delivery and status-client tests. Run race tests for touched concurrent paths
  and relevant securestore tests if storage behavior changes. Follow existing
  build prerequisites; ask before tests requiring execution outside the sandbox.
- [x] Validate processor/tap LI build parity and the non-LI boundary with the
  existing build targets, including `make verify-no-li`. Run `make manual-check`
  and `make manual` after manual changes. Address failures attributable to this
  work; report unrelated blockers rather than expanding scope silently.
- [x] Review the final diff and fixtures for sensitive data. No operational
  captures, real identifiers, deployment mappings, traffic statistics, private
  paths or report attachments belong in the repository or commit message.
- [x] Check off only tasks whose behavior and checks are actually verified.
  Record material residual heuristic limitations and validation results in this
  plan, then commit the implementation and updated plan together. Do not mark
  private replay classification or deployment validation complete based solely
  on synthetic tests.

## Verification and closure record

The bounded closure audit verified the implemented scope. Its two findings were
fixed: exact SIP usernames retain valid semicolons and pre-host question marks,
and stale buffered media increments the existing lifecycle-suppression counter
once at its rejection boundary. Scoped/unscoped identity regressions and both
stale-generation and stale-incarnation regressions pass.

| Check | Result |
| --- | --- |
| Affected LI, delivery, encoder, processor, processor/tap config and status package suites | Passed on the final repaired worktree |
| Affected correlator, URI/profile, processor integration, config and telemetry families with `-race` | Passed after the final repairs |
| Shared config/status tests with non-LI `all` build tags | Passed |
| Securestore package regressions | Passed |
| `make processor-li tap-li verify-no-li` | Passed on the final repaired worktree |
| `make manual-check manual` | Passed after the final documentation/translation changes; every configured edition verified |
| Formatting, diff whitespace and sensitive-data checks | Passed |

Tests requiring host filesystem ownership or socket access ran outside the
sandbox with user approval. No security checks were bypassed. The processor tests
exercise actual TLS delivery, immutable fan-out bytes, sequence contexts and
journal admission/replay, in addition to correlator-level fixtures.

No new topology-based collision veto was introduced: the constructed valid-chain
and unrelated-session cases can present indistinguishable weak evidence. Existing
trusted-evidence conflict rejection and multi-group ambiguity rejection remain.
The opt-in weak rules retain this documented limitation; canonicalization is not
a claim of unique session reconstruction. With profiles enabled, unsupported
post-host URI header queries suppress weak keys, and local service-code telephone
identities retain exact context instead of entering numeric rewrites.

The response queue is volatile, no store migration was introduced, and retained
IDs remain unchanged across restart/configuration changes. Private deployment
replays, their classification and MDF/profile qualification were not performed
or represented as passed; they remain the optional operator work below.

## Optional operator validation

Private capture reconciliation, deployment-specific rewrites, real task-density
measurements and MDF/profile validation remain operator activities outside this
repository plan. They are not prerequisites for authoring or testing the generic
implementation. If separately authorized, run the implemented policy with its
effective configuration recorded, classify suspected cross-session merges using
independent evidence and report coverage separately from correctness. Keep all
operational evidence outside the repository and do not infer compliance from
grouping counts alone.
