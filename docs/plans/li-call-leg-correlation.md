# LI call leg correlation implementation plan

**Date:** 2026-10-08

**Status:** implementation verified and closed; commit reference pending recording

**Scope:** processor and tap SIP/RTP X2/X3 delivery with `li` enabled

## Purpose and scope

Assign one X2/X3 Correlation ID to independently authorized SIP legs that the LI
correlator can associate with one communication. Each leg keeps its selected ID
after first publication while its decision is retained. The MDF maps that shared
Correlation ID, in the agreed interception/source context, to its own CIN.

Correlation changes the PDU Correlation ID and consequent Sequence Numbers. It
does not change task authorization, packet selection, content policy, direction,
payload, destinations, call admission, or delivery/replay authorization. It does
not allocate CINs, select one content leg, deduplicate content, change the TUI
correlator, or correlate across processor instances. All matching methods are
independently enabled and off by default. RADIUS remains on its existing path.

Grouping is best effort. Heuristics and reused origins can falsely merge calls;
arrival order, missing evidence, bounds and blind periods can leave calls split.
Preserve these limitations instead of adding mandatory qualification or
unsourced performance gates. Default windows and counts are configuration
starting points, not latency, throughput, CPU, RSS, or soak acceptance targets.

## Existing integration points

| Area | Existing files and behavior | Planned change |
| --- | --- | --- |
| Authorized task lookup | `internal/pkg/li/manager.go`: `ProcessPacketWithProvenance` validates provenance, resolves active tasks, then calls `PacketProcessor` once per task | Add a packet-scoped preparation hook with the matched task set before fan-out; retain admission checks |
| Encoding and delivery | `internal/pkg/processor/processor_li.go`: `initLI`, `SetPacketProcessor`, X2 queueing, X3 reorder/spool paths | Own the correlator per processor instance and pass one selected ID through all task/destination paths |
| Encoder identity | `internal/pkg/li/x2x3/x2_encoder.go`, `x3_encoder.go`, `sequence.go` | Supply the selected ID before allocating the full sequence context |
| Call retention | `internal/pkg/processor/call_lifecycle.go`, LI finalization subscriptions | Start terminal grace without immediately deleting the correlation decision |
| Configuration | `internal/pkg/processor/processor.go`, `cmd/process/flags_li.go`, `cmd/process/process.go`, `cmd/tap/flags_li.go`, `cmd/tap/tap.go` | Add equivalent processor/tap correlation configuration and non-LI stubs |
| Protected storage | `internal/pkg/securestore/`, LI state/key integration | Separate authenticated correlation store with bounded state, rotation and commit-outcome handling |
| Status | `api/proto/management.proto`, generated management code, processor LI stats, `cmd/show/status.go` | Add aggregate correlation telemetry without identities |

Use responsibility-based filenames, for example `call_correlation.go`,
`call_correlation_store.go`, `call_correlation_sdp.go`, and
`processor_li_correlation.go`; do not name files after implementation steps.
Keep runtime implementation LI-tagged. Share configuration types only where
required by existing non-LI build boundaries. Reuse existing parsers and secure
storage primitives; no new dependency is required by this plan. If one becomes
necessary, verify the latest stable release before adding it.

## Implementation contract

### Identity, concurrency and publication

The group ID is the existing FNV-1a 64-bit hash of its first leg's Call-ID. An
adopted child receives the group's ID. Single-leg calls keep their existing ID,
and RTP without an authoritative Call-ID keeps the current SSRC fallback.
Call-ID remains the decision key; forked dialogs share that decision.

Retain both standalone and adopted decisions in memory. Eligibility for adoption
is an initial INVITE or a response to an unknown initial INVITE transaction.
Re-INVITEs, known transactions, late signaling, and X3-first publication cannot
reconsider an existing decision. Track transaction identity with Call-ID,
From-tag and top Via branch, plus CSeq/method needed to validate corresponding
responses. A present, valid CSeq of zero is eligible; distinguish it from absent
or malformed unparsed metadata. Infer initial setup conservatively when capture
evidence is missing.

Resolve a packet once across matching tasks. Snapshot eligible task identities
with activation generations and administrative state incarnations; later admission
remains authoritative. A stateless manager uses a fresh runtime incarnation so
reused XIDs/generations cannot extend restored groups. Bound common-task contexts
to 1024 identities; oversized contexts disable adoption rather than truncating
membership. A group's
common tasks are the intersection across members at their decisions. Joining
shrinks this intersection atomically. Changed, expired or reactivated task
generations cannot admit a new leg through stale membership.

Serialize first decisions per Call-ID and protect shared candidate indexes and
group intersections across different Call-IDs. Two workers joining one group
must not each observe an outdated intersection. Specify lock ordering and keep
registry/admission calls outside conflicting locks. Do not use shared encoder
state or mutate packet metadata as a temporary Correlation ID override.

Select/reserve the ID before encoding. Define publication consistently as entry
into the existing deliverable queue, reorder buffer or spool, not successful
network transmission. Once any task/destination can expose the bytes, the ID
cannot be rolled back. Preserve the existing non-atomic destination fan-out.
Define safe behavior for encode failure, no destinations, rejected queueing and
uncertain admission results; retaining a conservative provisional pin is allowed,
but dropping a published decision is not. Count final outcomes once per leg.

### Matching hierarchy

| Precedence | Method | Behavior |
| --- | --- | --- |
| 0 | Retained decision | Always reuse it; no regrouping |
| 1 | H: configured trusted session headers; P: trusted parent reference | One exact stage; conflicting or ambiguous trusted evidence is terminal |
| 2 | S: parsed SDP origin | Unique usable match wins; absent, unusable or ambiguous evidence falls through |
| 3 | R1: address chaining plus called number | Unique group wins; multiple groups leave the leg separate |
| 4 | R2: exact calling/called number pair | Only where no address match exists; unique group wins |
| 5 | R1 rewritten-number fallback | Only where no called-number candidate exists; one eligible address candidate required |

All methods enforce common tasks and bounds. H/P win over weaker evidence;
contradictory trusted H values exclude fallback candidates. SDP differences alone
do not veto address/number matching. Configuration enables methods but does not
reorder them. No retrospective group merges are permitted.

H reads the header names configured in `session_headers`, including proprietary
names; it is not restricted to a built-in allowlist. Header names are matched
case-insensitively and keys are namespaced by normalized header name and value
interpretation. Session-ID uses the initiating UUID: local in an initial INVITE,
remote in a response-only observation. Reject missing, nil and malformed UUID
keys. P-Charging-Vector uses parsed `icid-value`. Every other configured header
uses complete-value matching by default: trim surrounding whitespace, preserve
case and internal content, and compare the resulting nonempty value exactly.
Do not truncate at a semicolon or guess proprietary parameter semantics. Missing
or empty values supply no key; conflicting repeated values cannot produce an
authoritative match. Multiple configured headers retain the existing agreement
and conflict rules. Enable H/P only where signaling supplies trustworthy values.
Parent headers contain one exact,
case-preserved Call-ID after surrounding whitespace is trimmed. Resolve only a
retained parent's decision, including an adopted parent's group. Unknown,
self-referencing, malformed, conflicting or ineligible parent references leave
the child separate. A later parent does not reconsider a published child.

R1 compares observed initial INVITE transport addresses, including configured
alias sets, within `address_window` and before that transaction's final response.
Compare complete canonical calling/called identities rather than phone suffixes;
document number extraction and normalization without operator-specific rewrites.
Matching-number R1 requires all qualifying candidates to resolve to one group.
R2 uses the exact number pair and `number_window`. Symmetric adjacent-hop lookup
uses capture timestamps, but cannot merge groups already published separately:
A, C, B arrival in an A → B → C chain remains split.

### SDP origin and suspension

S compares `(username, sess-id, nettype, addrtype, unicast-address)` as parsed
session identity. Version is revision metadata. Preserve full values without
32-bit narrowing or silent truncation, while enforcing explicit input-size
bounds. Do not substitute `c=` addresses or RTP endpoints. Separate offer/answer
roles; unknown roles provide no S evidence and never hold first publication.
Valid `-` usernames and fixed session IDs remain valid.

Gather reuse evidence before matching and independently of final group
membership. Distinct initial transactions retain earliest `first_seen` and latest
`latest_start` capture timestamps. A span greater than the reuse window, or
contradictory valid keys of the same H type, suspends that origin. Repeated packet
observations and retransmissions do not count as new transactions. Reuse inside
the window can still falsely merge calls; late legitimate legs can be suspended.

Observation/suspension history has its own bounded cache. An observation expires
at processor elapsed `last_seen + observation_ttl`; only distinct initial
transactions refresh last-seen, preserving earliest capture time. Require the
TTL to exceed the reuse window. Sparse reuse after expiry is undetectable from
the forgotten history. Matching origin indexes remain bounded by candidates.

A suspension has a fixed current deadline and a boolean recording distinct
qualifying transactions observed during that period. Observations do not move
the deadline. At expiry, renew for another suspension period and clear the flag
if it was set; otherwise remove the entry. Retransmissions never renew it. After
qualifying transactions stop, removal occurs within at most two suspension
periods. Process expiry and new observations atomically, including at boundaries.

At origin-cache capacity disable S rather than evict retained history or accept
an untracked origin. Continue enabled H/P/R1/R2 under their own rules. At release,
start fresh bounded history; neither suspension nor release regroups old legs.

### Retention, restart and protected persistence

Refresh decision activity on publication, including RTP. Retain terminal decisions
for grace aligned with BYE timewait. Expire inactive decisions using the existing
configured call lifetime and never evict published decisions to make room.
Expire candidates by windows and relevant initial final responses, retaining
transaction history for the decision horizon. Define candidate, transaction and
string-size accounting so secondary indexes cannot bypass configured limits.

At start, and whenever a decision cannot be recorded at capacity, enter or extend
a blind period for `decision_horizon`. No new leg is adopted in that period;
restored adopted decisions still apply. Preserve the explicit limitation that
transactions or forwarding delays exceeding the horizon can defeat protection
of unpersisted standalone decisions. This is conditional restart behavior, not
an absolute durability guarantee.

Persist adopted decisions in a dedicated encrypted store. Do not mix runtime
updates into administrative snapshots. Bind store identity, purpose, schema,
key usage, locking and protected paths using securestore. Persist group/context
metadata needed to restore decisions without accepting new members through stale
task generations. Candidate and origin caches can restart empty. Restore only
authenticated, valid, retained entries within bounds; corrupt storage must not
be silently replaced with an empty file. Specify operator recovery through the
existing secure-storage patterns.

Attempt the adopted write before publication. Committed uses the adopted ID;
confirmed NotCommitted records standalone. Uncertain uses the adopted ID and
retains bounded retry state until resolved. Never switch a published leg back
to standalone because a retry fails. A crash before uncertainty resolves can
lose the adopted ID; this is an explicit exception to restart stability. Preserve securestore
cryptographic limits and fault handling even when retrying. Refreshes, terminal
state and deletion must be durable enough to enforce the documented retention
policy on restore, without stale retries resurrecting removed generations.

## Configuration contract

Equivalent keys belong under `processor.li.correlation` and
`tap.li.correlation`. Preserve YAML/environment configuration conventions; add
CLI bindings only consistently with the existing LI command contract.

`session_headers` selects which session headers participate in H. An empty list
disables H; arbitrary valid SIP header names are accepted. For example,
`["Session-ID", "P-Charging-Vector", "X-Proprietary-Session-ID"]` enables the two
standard parsers and complete-value matching for the proprietary header. This
example is opt-in configuration, not the default. `parent_call_id_headers`
separately selects headers whose values reference another leg's Call-ID.
There is no requirement to configure Session-ID: a deployment may select only
P-Charging-Vector, only a proprietary header, or a combination of headers.
The same `session_headers` setting selects the headers and dispatches their value
parsing: Session-ID and P-Charging-Vector use the standard parsers described
above; other names use complete-value matching. Configuring several headers
does not change the agreement and conflict rules or their position in the
matching hierarchy.

```yaml
correlation:
  session_headers: []
  parent_call_id_headers: []
  sdp_origin_matching: false
  sdp_origin_reuse_window: 30s
  sdp_origin_observation_ttl: 10m
  sdp_origin_suspend: 10m
  sdp_origin_max_tracked: 10000
  address_chaining: false
  address_chaining_rewritten: false
  number_chaining: false
  address_window: 2s
  number_window: 500ms
  node_aliases: []
  decision_horizon: 5m
  terminal_grace: 30s
  store_file: ""
  store_key_file: ""
  store_key_id: ""
  store_read_keys: []
  max_candidates: 10000
  max_records: 100000
```

Validate durations, capacities, header names, alias sets and store/key settings.
Reject an enabled S configuration with observation TTL no greater than its reuse
window. Resolve active-call lifetime from the existing call lifecycle setting
rather than inventing an additional acceptance lifetime. An empty store path
means no restart persistence, not plaintext storage. Document how an explicitly
configured store obtains its authenticated keyring and rotation settings.

## Step 1: framework, H and matching-number R1

- [x] Add correlation configuration and validation types, processor/tap plumbing,
      LI build-tag separation, and an entirely disabled compatibility path.
- [x] Add packet-level manager preparation after provenance and active-task
      resolution, before fan-out; preserve task/call re-admission and RADIUS routing.
- [x] Implement per-Call-ID decision reservation/publication, group common-task
      intersections, atomic group updates and bounded transaction/candidate indexes.
- [x] Implement H's standard parsers and complete-value matching for arbitrary
      configured headers, trusted conflicts and matching-number R1, including
      alias validation, symmetric lookup and relevant final-response handling.
- [x] Extend X2/X3 encoder entry points to accept the selected ID before sequence
      allocation; preserve default wrappers, explicit-payload and batch behavior.
- [x] Integrate one packet-scoped result through X2, X3-only, reorder, journal,
      retry and multi-destination paths without rewriting replayed PDU bytes.
- [x] Implement decision retention, terminal grace, activity refresh, capacity
      fallback and blind-period extension; preserve restored IDs during blindness.
- [x] Implement the dedicated authenticated store, configured keys, lock/path
      protection, bounds, rotation, restore and all three commit outcomes.
- [x] Bound retry work and safely terminate it on generation retirement/shutdown;
      handle errors with context and privacy-preserving structured logs.
- [x] Add aggregate status schema and processor/show rendering: final outcomes,
      winning rules, group-size buckets, counts/limits, blind state, persistence
      activity and unresolved uncertainty. Update generated protobufs normally.
- [x] Complete step 1 unit, race and integration cases from the validation matrix.
- [x] Update operator documentation and every manual language for step 1; format,
      validate, mark verified tasks complete and commit code plus this plan.

## Step 2: parent references and SDP evidence

- [x] Implement P parsing and retained-parent lookup with common-task checks,
      H/P agreement, unknown-parent rejection and first-decision stability.
- [x] Implement parsed full SDP origins, version handling, role separation and
      bounded matching indexes; reuse existing SIP/SDP facilities where suitable.
- [x] Implement independent pre-match reuse observations, separate TTL, suspended
      state, expiry-time renewal and conservative origin-cache capacity behavior.
- [x] Extend the hierarchy so trusted conflicts are terminal and unusable or
      ambiguous S evidence falls through without overriding trusted keys.
- [x] Extend configuration, final outcomes and per-rule observations; distinguish
      an S miss followed by successful R1 adoption from a standalone leg.
- [x] Complete parent/SDP/hierarchy tests, including retention and renewal boundaries.
- [x] Update all affected operator/manual editions; format, validate, check off
      verified work and commit code plus this plan.

## Step 3: weaker optional heuristics

- [x] Implement R2 with exact number pairs, its window and no-address-match rule.
- [x] Implement rewritten-number R1 fallback last, requiring one candidate and
      preserving terminal address/number ambiguity and trusted-key vetoes.
- [x] Verify independent switches, counters and documented false-merge behavior;
      neither method changes authorization or an already published decision.
- [x] Complete weak-rule tests and the final delivery invariant across processor
      and tap; update affected manual translations, validate and commit the
      verified implementation and completed plan checklist.

## Validation matrix

Use reserved example addresses, invented identities and deterministic fake clocks.
Compare actual decoded PDUs and task/destination products, not just map entries.

| Area | Required cases |
| --- | --- |
| Compatibility | All rules disabled, single leg, shared Call-ID, SSRC fallback, X2-only/X3-only/both, no LI in non-LI builds |
| Grouping | Two/four-hop chains; every three-hop arrival permutation; A,C,B remains split; aliases and multiple candidates already in one group |
| First decisions | Retransmissions, forks, re-INVITEs, response-first, mid-dialog, X3-first from a surviving hunter, task activation after signaling |
| Common tasks | A on X, B on X/Y, C on Y rejected; concurrent intersection shrink; expiry, edits, generation reactivation and admission races |
| H/P | UUID nil/malformed/response remote handling, ICID parsing, proprietary complete values including semicolons, case-insensitive header names, case-preserved values, whitespace/empty/repeated values, namespaced keys, multi-header agreement/conflicts, H/P conflict, parent already adopted, unknown/later/self parent |
| SDP | Preserved origin with changed Call-ID/version, long/large values, different origins, offer/answer/unknown/delayed roles, valid '-' username |
| SDP history | Isolated t=0/t=40s use with defaults suspends; earliest timestamp retained under out-of-order arrival; distinct-use refresh; retransmissions do not refresh; sparse use after TTL loses history |
| SDP suspension | Distinct use sets renewal flag without moving deadline; expiry renews and clears flag; no distinct use releases; retransmissions do not renew; continuous static reuse has no release gap; quiet-time removal within two periods |
| Hierarchy | H/P prevail over S/R1; trusted conflict stops; usable unique S precedes R1; ambiguous/suspended/capacity-disabled S falls through; weaker ambiguity stops |
| Weak rules | Exact pairs, unseen hop, simultaneous calls inside/outside window, redial outside windows, rewritten numbers, no suffix matching, documented false merges |
| Bounds/retention | Each configured limit and secondary-index bound; no published-record eviction; blind deadline extends after each lost decision; grace/expiry and late BYE/response |
| Persistence | Committed/NotCommitted/Uncertain injection, restart before/after resolution, authenticated corruption, stale/oversized state, rotation, locking, late retries and shutdown |
| Delivery invariant | Same authorized task/destination products, policy, direction and payload; only group IDs and dependent sequences change; preserve full sequence scope, X2/X3 separation and fan-out semantics |
| Telemetry | Once-per-leg final outcome, S observation plus R1 adoption, limits/persistence/blind status, no raw Call-IDs, numbers, addresses or payloads |

- [x] Run focused tests with `go test -tags 'all li'` for LI, encoders, processor,
      process/tap configuration, and affected status/storage packages.
- [x] Run relevant race tests for decisions, shared groups, expiry, publication,
      retries and task/call finalization using `go test -race -tags 'all li'`.
- [x] Run the applicable full-suite regression check (`go test -tags 'all li' ./...`)
      and non-LI checks; preserve established authorization/expiry/storage tests.
- [x] Build processor-li and tap-li and run `make verify-no-li`; test role-specific
      builds when configuration or build-tag boundaries change.
- [x] Update `docs/LI_INTEGRATION.md`, process/tap README content, and affected
      manual LI/config/command/status sections. Follow `docs/manual/README.md`,
      translate changed text in every configured catalog (currently `de` and
      `ca`), resolve affected fuzzy entries, and run `make manual-check` and
      `make manual` before considering manual changes complete.
- [x] Format changed files before staging, run appropriate vet/generated-code
      checks, inspect the final diff, and record exact validation results here.

Replay on real deployment captures may inform window tuning and aggregate
observations, but is optional evaluation rather than an unsourced acceptance
gate. Do not export sensitive capture contents. If a required check is blocked
by an unrelated issue, follow the repository instruction to report that issue
instead of repairing unrelated functionality. Ask before running tests outside
the sandbox, and clean any temporary cache created for this work.

## Completion evidence

The implementation uses one shared processor runtime for distributed process and
standalone tap. One combined implementation commit covers all three steps; each
method retains its own switch and tests. The all-disabled manager path preserves
its original per-task lookup/callback order and allocates no correlator.

Publication counters count retained decisions once per leg. At record capacity,
`unrecorded_decisions` counts lost reservation attempts separately because an
unretained Call-ID cannot be deduplicated indefinitely under the record bound.
The status includes the actual correlation store's protected-storage telemetry.

The bounded closure review identified two findings: valid zero-CSeq transactions
were rejected, and disabled preparation changed legacy callback ordering. Both
were fixed and verified by focused regressions; the zero-CSeq regression passes
real packet frames through `processBatch`, the manager, and TLS PDU delivery.
The integrated post-fix review found no supplemental findings.

Final closure outcome: **CLOSED**, after one discovery round, one primary repair
batch and one integrated post-fix review. No supplemental findings or required
external deferrals remain. The design's documented best-effort/restart limitations
remain product behavior; no optional capture qualification was made a gate.

Final validation on 2026-10-08:

- `go test -tags 'all li' ./...`: passed, 119 tested packages.
- `go test -tags all ./...`: passed, 117 tested packages.
- `go test -race -tags 'all li' ./internal/pkg/li ./internal/pkg/li/x2x3
  ./internal/pkg/li/delivery ./internal/pkg/processor ./internal/pkg/statusclient
  -run 'Test(CallCorrelation|Correlation|SDPOrigin|Processor.*Correlation|LI.*Correlation)'
  -count=1`: passed all five packages, including actual batch-to-TLS and journal
  publication regressions. Separate full securestore normal/race suites passed.
- Processor-li and tap-li command/config/offline migration checks passed.
- `go vet -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/...
  ./cmd/process ./cmd/tap ./cmd/migrate ./internal/pkg/statusclient`: passed.
- `make processor-li tap-li verify-no-li`: passed after the final code fixes.
- Normal `protoc` regeneration matched the checked generated management source.
- `make manual-check manual`: passed; `de` and `ca` each translated all 5567
  current messages; all editions passed heading, example, code and link checks.
  The existing mdbook/gettext version warning was nonfatal.
- Changed Go files were formatted with `gofmt`; `git diff --check` passed.

Secure-storage fixtures require owner-consistent ancestry. Sandbox attempts failed
at that existing protection; the user approved outside-sandbox tests and all
fixture-dependent required checks passed there. Protection was preserved.

| Step | Commit | Validation and material limitations |
| --- | --- | --- |
| Framework, H and R1 | Combined implementation; reference pending | Full LI/non-LI suites, encoder and actual delivery invariants, storage and race checks passed |
| P and S | Combined implementation; reference pending | Parent, framed SDP/roles/history/suspension/hierarchy tests and race checks passed |
| Weaker heuristics | Combined implementation; reference pending | Exact pairs, no-address rule, rewritten fallback, independent switches and decoded delivery tests passed |

## References

[ETSI TS 103 221-2 §5.2.8](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.10.01_60/ts_10322102v011001p.pdf)
defines the shared X2/X3 Correlation ID; it does not validate heuristic rules.
[RFC 3261 §8.1.1.5](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.5)
defines SIP CSeq bounds, including valid zero values.
[RFC 7989](https://www.rfc-editor.org/rfc/rfc7989.html) defines Session-ID UUID
semantics. [RFC 8866 §5.2](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.2)
defines SDP origin identity and version.

The local OpenLI inspection found shared Call-ID/CIN mapping through Session-ID
or SDP origin in `src/collector/sip_callstate_tracker.c`; VoIPmonitor sniffer
provided the parent Call-ID precedent in `sniff.cpp:process_packet__merge`.
Their implementations inform matching opportunities, not lippycat authorization,
durability, or performance acceptance requirements.
