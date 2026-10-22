# X1 v1.23.1 selective IRI policy support

**Date:** 2026-10-22

**Baseline:** `74909955` (lippycat v0.13.1)

**Status:** complete for the documented X1 POI capability profile

## Objective and public references

Implement selective IRI delivery before accepting or declaring X1 v1.23.1.
Preserve the existing revision gate until policy provisioning, persistence,
reconciliation, enforcement, and interoperability checks are complete.

Use synthetic fixtures and public specification references. Exclude private
review material, deployment identifiers, endpoints, credentials, captured
traffic, and operational incidents from this plan and its fixtures.

Authoritative sources:

- [ETSI TS 103 221-1 v1.23.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.23.01_60/ts_10322101v012301p.pdf),
  especially generic-object operations in clause 6.8 and selective IRI delivery
  in Annex F.
- [Published X1 schemas](https://forge.etsi.org/rep/li/schemas-definitions/-/tree/spec/103221-1/1.23.1/103221-1).
- [ETSI TS 103 120 v1.24.1](https://www.etsi.org/deliver/etsi_ts/103100_103199/103120/01.24.01_60/ts_103120v012401p.pdf),
  especially clauses 7.7, 7.8, and 8.2.14.
- [Published TS 103 120 schemas](https://forge.etsi.org/rep/li/schemas-definitions/-/tree/spec/103120/1.24.1/103120/schema/xsd)
  and [dictionaries](https://forge.etsi.org/rep/li/schemas-definitions/-/tree/spec/103120/1.24.1/103120/dictionaries).

The earlier assessment in
`docs/research/etsi-x1-v1.23.1-iri-policy-support.md` predates the current
encrypted state format and packet-processing implementation. Use the current
code and the sources above where that assessment is outdated.

## Required behavior and deployment profile

Rules have positive, unique order values and run in ascending order. Criteria
within a rule combine with AND; alternatives within a criterion combine with
OR. Evaluation stops at the first matching rule across the ordered policy
list. No policy or no matching rule means delivery unchanged. Empty or invalid
policy definitions must be rejected during provisioning.

The standard IRI actions are `Delivered` and `NotDelivered`. The published ETSI
IRI event dictionary defines `All`; its NF type dictionary has no values.
Additional national dictionary values require explicit, validated mappings to
facts that lippycat actually observes. Raw SIP messages and RADIUS codes must
not be presented as standardized IRI event identifiers. A handover-format
criterion requires a configured downstream format; emitting X2 alone does not
establish one.

The supported profile follows lippycat's existing point-of-interception role:

- [x] Resolve policy scope using X1 clause 4.1.4 and Annex C: task policies at
      this POI govern X2 generation; mediation policies govern HI2/HI3 delivery
      at an MDF. Implement task-level policies and reject mediation-policy
      references as unsupported. Do not reinterpret them as per-DID X2 rules.
      A separately provisioned downstream MDF cannot recover IRI suppressed
      upstream. No task-versus-mediation override option is needed here.
- [x] Document the missing published X1 IRI object adapter and the deployment
      adapter in `urn:lippycat:li:x1:iri-policy:1`. The
      published TS 103 120 IRI types extend `HI1Object`, whereas X1 generic
      operations require a type derived from `GenericObject`. The published
      X1 schema supplies a traffic-policy adapter but no IRI-policy adapter.
      Reuse the unchanged official IRI groups and document that the ADMF must
      use the same adapter for policy provisioning.
      Do not invent an ETSI namespace or claim the adapter is an ETSI type.
- [x] Preserve existing supported administrative compatibility while rejecting
      policy-bearing mediation contexts and other unsupported MDF features.
      Describe v1.23.1 support as a POI capability profile, not an MDF.

## Policy domain and evaluation

- [x] Add bounded policy, rule, dictionary, criterion, and rule-reference domain
      types independent of XML and the processor.
- [x] Validate object kinds, nonzero IDs and generations, complete references,
      rule ordering, criteria, action choices, and supported dictionary entries.
- [x] Compile immutable policy snapshots, retaining their source object
      generations. Prevent mutation through caller-owned slices or pointers.
- [x] Implement the specified ordering, AND/OR semantics, first-match behavior,
      and default delivery. Treat unavailable required facts as an explicit
      enforcement error, not an ignored criterion.
- [x] Test invalid graphs and limits, ordering, matching, national dictionary
      validation, missing facts, default behavior, and snapshot immutability.

## Schemas and X1 wire operations

- [x] Vendor the selected published schemas and dictionaries with source tags,
      hashes, and a reproducible generation command using a pinned tool.
      Record deterministic offline import-location adjustments separately.
- [x] Add the two policy-reference fields and the agreed generic-object wire
      types. Validate representative messages against the complete XSD set.
- [x] Preserve namespace scope when decoding envelope messages and nested
      polymorphic objects. Resolve `xsi:type` by namespace URI; reject unknown
      types, duplicate fields, invalid choices, and unsupported content.
- [x] Route CreateObject, ModifyObject, DeleteObject, GetObject,
      ListObjectsOfType, DeleteAllObjects, and GetAllGenericObjectDetails.
      Return concrete standard responses and error request types.
- [x] Implement standard duplicate-create rejection (including an identical
      existing object), full-replacement modification, URI-qualified type names,
      and safe deletion of referenced objects. Implement DeleteAllObjects or
      its explicitly agreed disabled behavior with the standard error.
- [x] Preserve task references through activation, modification, readback, and
      the ADMF client. Decode mediation references so that capability validation
      explicitly rejects them. Extend capabilities without accepting unrelated
      unsupported features.

## Administrative graph and durability

- [x] Store detached object definitions and dependency bindings in the existing
      administrative state. Include policy references and source generations in
      canonical task and delivery definitions.
- [x] Extend encrypted bounded state decoding and encoding with an explicit
      migration from state version 2. Preserve existing plaintext migration,
      validation limits, and fail-closed restore behavior.
- [x] Compile and validate a candidate graph before changing live authority.
      Integrate object changes with the existing lock order and durable
      administrative transaction barriers.
- [x] For shared policy or rule changes, reserve all affected task generations
      and revocations together. Revoke queued X2 and X3 from old affected
      generations before publishing the new graph. Do not rely on the ordinary
      X3-only task-modification cancellation path.
- [x] Recover interrupted grouped transactions without exposing mixed old and
      new policy authority. Definite reservation failure must retain the old
      graph; uncertain commits must remain fail closed.
- [x] Extend the same authoritative GetAllDetails snapshot to generic objects.
      Track object-list completeness separately. Missing, malformed, or
      incomplete graphs must not authorize restored policy-dependent tasks or
      queued replay. Preserve existing partial-snapshot safeguards.
- [x] Test dependent deletion, shared updates, rollback, interrupted commits,
      migration, restoration, incomplete snapshots, and stale queued products.

## Processor and operator configuration

- [x] Add validated deployment-profile configuration for supported national
      event mappings, known NF types, and downstream handover formats. Bind its
      semantic revision into policy-dependent task and replay authority so a
      changed mapping cannot reuse old delivery authorization. Keep configuration consistent across process
      and tap entry points and build variants.
- [x] Evaluate SIP policy after task association and required shared signaling
      learning, before X2 encoding and enqueue. Preserve correlation and media
      direction learning needed by X3.
- [x] Evaluate RADIUS policy before durable correlation and sequence allocation.
      Keep X3 delivery independent of IRI suppression.
- [x] Add distinct suppression and evaluation-error counters with a single
      increment owner. Expose graph status without logging policy content,
      target identities, or other sensitive values.
- [x] Verify task scope and rejection of MDF policy scope, multiple simultaneous tasks with
      different policies, no sequence allocation for suppressed X2, and X3
      continuation when IRI is suppressed using real TLS delivery fixtures.

## Documentation, verification, and release gate

- [x] Document the supported deployment profile, schema adapter, dictionaries,
      lifecycle behavior, restart/replay rules, configuration, and limitations.
      Update outdated architecture and research statements.
- [x] Update affected manual source and every configured translation, then run
      `make manual-check` and `make manual`.
- [x] Run focused policy, X1, administrative, persistence, and processor tests;
      required race tests; LI and non-LI build variants; and applicable vet
      checks. Record concrete evidence below.
- [x] Perform one bounded implementation closure review and resolve its fixed
      finding list. Do not introduce unsourced performance acceptance gates.
- [x] Only after the feature and agreed profile are verified, accept and declare
      X1 v1.23.1 and update version-negotiation tests. Preserve rejection of
      newer unsupported revisions.
- [x] Format changed files and commit the implementation and this plan.

## Verification evidence

- Policy evaluator race tests passed, including strict graph validation,
  immutable snapshots, first-match ordering, and known-empty versus missing facts.
- X1 race tests and vet passed, including real XSD fixtures, namespace scope,
  generic CRUD, ordered task references, the v1.23.1 declaration, and v1.24.1
  rejection before mutation. Schema generation is deterministic.
- Processor IRI race tests passed with real TLS delivery: task isolation,
  raw-message national mapping, suppression before sequence/correlation allocation,
  X3 continuation, and separate telemetry counters.
- Full process/tap race suites passed; the five LI help snapshots include the
  new profile flag.
- Full non-LI `go test -race -tags all ./...` passed.
- Full `GOTOOLCHAIN=go1.27.3 go test -race -tags all,li ./...` passed after
  correcting the two new test fixture assumptions.
- `make build-matrix` passed all nine non-CUDA binary builds, package compile
  partitions, and LI/non-LI vet partitions. CUDA linking is outside this change.
- `make manual-check` and `make manual` passed, with all 5,912 current messages
  translated in German and Catalan and all three editions built. The existing
  mdBook/gettext version warning did not prevent validation or generation.

- Administrative race tests passed for grouped checkpoint failures, state-v2
  migration, source/profile changes after restart, detached profile ownership,
  and the same-response graph/task admission barrier. Missing confirmation
  withdraws authority; pending promotion and replay cannot cross the barrier.
- `make verify-no-li` passed.

The bounded closure campaign is **CLOSED** for this implemented profile. It used
one discovery round, one primary repair batch, one affected post-fix review, and
one supplemental repair batch. All four concrete XML findings are fixed:
original QName namespace/duplicate-attribute handling, positive-integer lexical
forms, legacy namespace-free container compatibility, and bounded namespace
expansion before mutation or snapshot confirmation. The final Go 1.27.3 X1 and
schema race tests passed; the complete LI manager race suite passed after those
fixes, and final `go vet -tags all,li ./...` passed. Authored-file formatting
and whitespace checks passed. The two verbatim XML Signature schema copies
retain upstream whitespace to preserve their recorded source hashes. Startup
diagnostics also include generic-object failures.

Live ADMF/MDF deployment acceptance was not exercised. The documented adapter
agreement, national dictionary mappings, and receiver compatibility remain
operator deployment requirements; no external interoperability result is claimed.
No unsourced performance gate was introduced.
