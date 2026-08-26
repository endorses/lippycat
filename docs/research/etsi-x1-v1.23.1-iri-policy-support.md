# ETSI X1 V1.23.1 full-support assessment

**Date:** 2026-08-26

**Repository baseline:** `b20d17c` (v0.10.1)

**Decision:** defer V1.23.1; retain V1.22.1 as lippycat's declared and newest
accepted X1 revision until the work described here is complete

## Executive summary

ETSI TS 103 221-1 V1.23.1 adds selective IRI delivery provisioning. Its core
X1 schema delta from V1.22.1 is small: optional ordered references to IRI Policy
generic objects are added to `TaskDetails` and `MediationDetails`. The referenced
objects and their rules come from ETSI TS 103 120.

The XML change is easy to parse. Correct implementation is not. An IRI policy
can determine whether matched intercept-related information is delivered. If
lippycat accepts a policy-bearing task but ignores the policy, it can deliver
more IRI than was provisioned. That is a fail-open authorization error.

Full support requires all of the following as one coherent feature:

- V1.23.1 and referenced TS 103 120 schema models;
- X1 generic-object lifecycle operations;
- durable IRI Policy and IRI Rule storage with referential integrity;
- preservation of task-level and per-mediation policy scope;
- deterministic ordered rule evaluation;
- enforcement after task association and before X2 encoding/enqueue;
- atomic modification, persistence, reconciliation, status, audit, and metrics;
- conformance, negative, lifecycle, restart, race, and performance tests.

Until that feature is complete, lippycat should reject V1.23.1 at the revision
gate. This avoids both silent policy omission and a misleading partial-support
claim.

## 1. Normative change in V1.23.1

V1.23.1 contains two change requests:

- CR077r2 corrects references in the TargetIdentifier format table. This is
  editorial for lippycat.
- CR078r1 adds selective IRI delivery provisioning.

The V1.23.1 XSD adds:

```xml
<xs:element name="listOfIRIPolicyReferences"
            type="ListOfIRIPolicyReferences"
            minOccurs="0"/>
```

to both `TaskDetails` and `MediationDetails`. The list contains zero or more
`iRIPolicyReference` values, each a `GenericObjectID` UUID.

Normative Annex F states that IRI policies may be associated with a task when
IRI from particular network-function types or particular IRI events should not
be generated or delivered. The IRI Policy and IRI Rule object definitions are
taken directly from ETSI TS 103 120.

Primary references:

- [ETSI TS 103 221-1 V1.23.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.23.01_60/ts_10322101v012301p.pdf)
- [ETSI LI schema repository](https://forge.etsi.org/rep/li/schemas-definitions)
- [ETSI TS 103 120 deliverables](https://www.etsi.org/deliver/etsi_ts/103100_103199/103120/)

### 1.1 Published-document discrepancy

The V1.23.1 XSD unambiguously adds the two reference fields, and Annex F
defines their meaning. In the published PDF, however, the extracted TaskDetails
and MediationDetails tables do not show corresponding rows, and Annex F refers
to stale table identifiers (`table 4` and `table C.1`). This appears editorial,
but it should be recorded in any eventual conformance statement.

For implementation, use the published XSD for wire structure and normative
Annex F together with the referenced TS 103 120 definitions for behavior. Do
not invent semantics to fill any remaining ambiguity; record and resolve it
against an ETSI correction or conformance profile first.

## 2. The referenced TS 103 120 policy model

The TS 103 120 IRI policy schema in the ETSI repository uses four important
structures.

### 2.1 IRI Policy object

An `IRIPolicyObject` is a generic HI1 object containing:

- an optional policy name;
- an ordered list of IRI Rule references.

Each rule reference carries a positive `Order` and an object identifier. Order
is therefore normative data, not presentation metadata.

### 2.2 IRI Rule object

An `IRIRuleObject` contains:

- zero or more criteria;
- an action represented by a dictionary entry;
- an action-parameters choice, currently empty in the published schema.

Each criterion is one of:

- `NFTypeCriteria` — one or more network-function type dictionary entries;
- `IRIEventCriteria` — zero or more IRI-event dictionary entries;
- `HandoverFormatCriteria` — a handover-format dictionary entry.

### 2.3 Actions and dictionaries

The ETSI dictionary currently defines two `IRIAction` values:

- `NotDelivered` — matching IRI is not delivered;
- `Delivered` — matching IRI is delivered.

The standard `IRIEvents` dictionary currently defines `All`. The standard
`NFType` dictionary is presently empty. The types nevertheless permit
dictionary-based values, so an implementation must define whether and how
non-ETSI dictionary owners are supported. Unknown dictionary owner/name/value
triples must not silently match or silently fall back.

### 2.4 Policy composition questions that must be fixed in code and tests

Before implementation, derive and document the precise TS 103 120 evaluation
algorithm, including:

1. how multiple criteria inside one rule combine;
2. how ordered rules combine and whether evaluation stops at the first match;
3. the default result when no rule matches;
4. the result of an empty policy or empty rule list;
5. how duplicate or missing order values are treated;
6. how multiple policy references on one task combine;
7. the precedence of mediation-level references over task-level references;
8. how unknown dictionary entries are handled;
9. whether `HandoverFormatCriteria` is meaningful at a POI that emits X2 rather
   than the final handover format;
10. whether suppression means no X2 PDU is generated, no PDU is enqueued, or a
    downstream mediation-specific action.

These are authorization semantics. Any unresolved case must fail provisioning,
not choose a permissive runtime default.

## 3. Current lippycat gaps

### 3.1 Schema model

The bundled `TS_103_221_01.xsd` and generated Go types are V1.22.1. They have
traffic-policy references but no IRI-policy references in either `TaskDetails`
or `MediationDetails`.

Go's `encoding/xml` ignores unknown elements. If the version gate were widened
without updating the model and validation, V1.23.1 policy references would
disappear during decoding while the task could still be acknowledged.

### 3.2 Generic-object X1 operations

The generated schema contains generic-object request and response types, but
`processRequestMessage` does not route the generic-object operations required
to manage policy and rule objects:

- `CreateObject`;
- `ModifyObject`;
- `DeleteObject`;
- `GetObject`;
- `ListObjectsOfType`;
- `DeleteAllObjects`;
- `GetAllGenericObjectDetails`.

They currently receive an unknown-request error. There is no generic-object
registry, dependency index, lifecycle service, or durable store.

### 3.3 Task and mediation model

`InterceptTask` stores one target list, one delivery type, one destination list,
and one effective start/end window. It does not preserve:

- task-level IRI-policy references;
- mediation-level IRI-policy references;
- LIID-specific mediation contexts;
- per-context delivery type, destinations, or policy overrides.

The X1 conversion code collapses `ListOfMediationDetails` into a single
representable time window. Full policy support cannot use that lossy model when
different mediation contexts under one XID have different policies.

### 3.4 IRI processing path

`Manager.ProcessPacket` resolves filter matches to tasks and invokes a packet
processor. `X2Encoder.EncodeIRI` then classifies supported SIP messages and
constructs an X2 PDU. No stable policy-evaluation boundary exists between task
association and X2 encoding/delivery.

Applying policy in the analyzer would be incorrect because one analyzed event
may match multiple tasks with different policies. Applying it globally in the
encoder would also be incorrect unless the complete effective task/mediation
context is passed in.

### 3.5 Persistence, reconciliation, and idempotency

Persistence schema version 1 stores tasks and destinations only. Policy objects,
rule objects, reference graphs, and compiled policy state are absent. Startup
and periodic reconciliation handle tasks and destinations, not generic objects.

Task equivalence and atomic modification also do not include policy references.
Adding policy after idempotent activation is implemented would require policy
references and their effective object generations to participate in the
canonical task definition.

### 3.6 Status and observability

Task-detail responses cannot return IRI-policy references. There are no metrics
for policy evaluation, suppression, invalid references, or object lifecycle
failures, and no audit history for policy changes that affect delivered IRI.

## 4. Required architecture

### 4.1 Schema and generated types

Vendor the exact published schemas needed for the selected conformance set:

- TS 103 221-1 V1.23.1 core X1 schema;
- the corresponding TS 103 120 IRI Policy, Core, Common, and dictionary
  definitions;
- the referenced TS 103 280 revision used by those schemas.

Record source tags and hashes. Regenerate Go types reproducibly rather than
hand-editing only the two fields. Generation must preserve XML namespaces and
polymorphic generic-object types; add custom unmarshalling if the generator
cannot decode abstract `GenericObject` instances and `xsi:type` safely.

The generated model should remain a wire model. Convert it into validated
domain types before any registry mutation.

### 4.2 Generic-object registry

Add a registry with immutable snapshots or deep-copy semantics for:

- IRI Policy objects;
- IRI Rule objects;
- their IDs, types, names, ordered references, criteria, actions, and revision
  or generation;
- reverse references from rules to policies and policies to tasks/mediation
  contexts.

Required invariants:

- object IDs are unique across supported generic-object types;
- object type is immutable unless the standard explicitly allows replacement;
- every policy reference resolves to an IRI Policy;
- every rule reference resolves to an IRI Rule;
- orders are valid and deterministic;
- referenced objects cannot be deleted while active tasks depend on them,
  unless an explicitly standardized atomic cascade exists;
- a modification is validated and compiled before replacing the live snapshot;
- readers see either the complete old graph or complete new graph.

Unsupported generic-object types should receive an explicit X1 error. They must
not be stored as opaque XML if lippycat could later acknowledge a task that
depends on their unknown semantics.

### 4.3 X1 generic-object handlers

Implement the full lifecycle necessary for independently managed policy
objects:

- create with schema, type, dictionary, and reference validation;
- modify atomically with dependent-policy revalidation;
- delete with reverse-reference checks;
- get and list with canonical response serialization;
- delete-all with authorization/configuration gating and dependency safety;
- include generic objects in all-details responses where required.

Handlers should use a narrow `GenericObjectManager` interface rather than
coupling XML parsing directly to storage. Error mapping must distinguish
duplicate ID, missing object, wrong object type, invalid reference, unsupported
dictionary, object in use, and malformed content.

### 4.4 Preserve mediation contexts

Introduce a domain model that does not collapse policy scope, for example:

```text
InterceptTask
├── XID, targets, default delivery and default destinations
├── task IRI policy IDs
└── mediation contexts[]
    ├── LIID
    ├── delivery type
    ├── start/end window
    ├── destination IDs
    └── effective or overriding IRI policy IDs
```

The exact representation must follow the standard's override semantics. It must
also define how a POI-only lippycat instance treats mediation fields intended
for an MDF. Fields irrelevant to the configured role may be ignored only where
the standard explicitly permits that behavior.

This model affects activation, modification, expiry, destination validation,
status responses, persistence, reconciliation, delivery fan-out, and
idempotency. It should be implemented as a domain-model migration rather than
special-casing policy lists in the X1 handler.

### 4.5 Compile policies at administrative time

Do not traverse UUID graphs and dictionary objects for every packet. On object
or task mutation:

1. resolve all references;
2. validate dictionary entries and supported criteria;
3. order the rules;
4. compile them into an immutable evaluator;
5. atomically publish a task/mediation policy snapshot.

Each compiled snapshot should carry the generations of every source object so
status, audit, and persistence can explain exactly which policy was enforced.
Changing a shared rule must compile all affected policies and dependent tasks
before publishing any of them.

### 4.6 Enforcement boundary

The desired runtime flow is:

```text
packet and protocol metadata
    -> filter match
    -> active task lookup
    -> candidate IRI classification
    -> effective task/mediation policy evaluation
        -> suppress with bounded metric/audit attribution
        -> or encode X2 and enqueue to the selected destination context
```

Policy evaluation must happen independently for each matched task and, where
applicable, each mediation context. X3 must not be suppressed by an IRI policy.
Correlation and sequence state must advance only according to the normative
meaning of suppression; this requires explicit tests for whether a suppressed
event consumes any X2 sequence number or creates session state.

The evaluator needs normalized facts:

- lippycat/network-function type;
- classified IRI event;
- applicable handover format, if known at this layer;
- task, LIID, and destination context.

Today lippycat's X2 encoder uses an internal SIP classification only to decide
whether to emit a PDU, while the downstream system derives detailed IRI
semantics from the raw SIP payload. Full policy support therefore requires a
stable mapping from lippycat's classifications to the TS 103 120 dictionary
entries accepted during provisioning. If no standards-based mapping exists for
a requested value, reject that policy.

### 4.7 Failure semantics

Fail closed at provisioning for:

- missing or wrong-type policy/rule references;
- unsupported criteria or actions;
- unknown dictionary owner/name/value combinations;
- ambiguous ordering;
- unsupported mediation-policy combinations;
- a policy that cannot be compiled for the current lippycat role;
- task activation while a referenced object update is incomplete.

A runtime evaluator error must not default to delivery. It should suppress the
affected IRI, increment a fault metric, retain bounded diagnostic context, and
report a task issue through the existing X1 fault mechanism where appropriate.
The exact report type and recovery behavior must be selected from the standard
rather than invented locally.

## 5. Lifecycle and concurrency semantics

### 5.1 Atomic mutations

Administrative mutations can affect active interception immediately. Use the
manager lifecycle serialization or an equivalent transaction boundary so that:

- creating an unreferenced object cannot affect traffic;
- activating a task publishes its registry state, filters, and compiled policy
  atomically from the runtime's perspective;
- modifying a rule shared by several active policies switches every dependent
  evaluator consistently;
- a failed compile or persistence write leaves the previous policy live;
- deletion cannot race with packet evaluation or task activation.

### 5.2 Object versioning

Use monotonically increasing object generations. A compiled policy should
record policy and rule generations, and a task should reference a complete
compiled snapshot rather than mutable object pointers. Old snapshots may remain
alive until in-flight packet processing releases them.

### 5.3 Idempotency

All generic-object operations and task reassertion need deterministic retry
behavior. At minimum:

- repeating an identical create after an uncertain response is a documented
  success or standards-defined duplicate response, without mutation;
- repeating an identical modify does not bump generations unnecessarily;
- task equivalence includes ordered effective policy references;
- object equality uses canonical domain values, not raw XML byte equality.

## 6. Persistence and reconciliation

Bump the local persistence schema and store:

- validated IRI Policy and IRI Rule objects;
- object type and generation;
- ordered references and reverse-reference data or enough information to
  rebuild it;
- task-level and mediation-level policy references;
- the source revisions needed to verify compatibility on restore.

Compiled evaluators should normally be rebuilt and revalidated from persisted
domain objects rather than serialized.

Restore must remain disarmed until an authoritative snapshot confirms tasks and
all referenced objects. Missing, corrupt, or incompatible policy state must
prevent the dependent task from being armed. Reconciliation order should be:

1. destinations;
2. generic rule objects;
3. generic policy objects;
4. tasks and mediation references;
5. compiled evaluators;
6. filters and activation.

An incomplete object snapshot must not trigger destructive reconciliation.
Conversely, an authoritative deletion must not leave an active task enforcing a
stale policy indefinitely. Define a safe task-fault/deactivation path for that
case.

## 7. Status, audit, and operational visibility

Implement:

- task-detail responses that preserve policy references and mediation scope;
- generic-object get/list responses;
- audit records for object creation, modification, deletion, failed reference,
  compilation, task binding, and effective-generation changes;
- counters by action and reason: evaluated, delivered, suppressed, no match,
  invalid runtime state, and evaluator fault;
- object and compiled-policy counts and generation information;
- rate-limited diagnostics that identify XID, optional LIID, policy ID, rule ID,
  and failure category without logging intercepted content or sensitive target
  values.

Policy suppression is expected behavior, not packet loss. It must not be mixed
with queue-drop or delivery-failure counters.

## 8. Security considerations

IRI policy is part of the interception authorization boundary. Treat its data
and lifecycle with the same controls as task provisioning.

- Validate XML size, nesting, list lengths, and generic-object graph limits.
- Bound the number of policies per task, rules per policy, criteria per rule,
  and affected dependents per update.
- Prevent cyclic or excessively deep reference graphs even if current object
  types should form a shallow graph.
- Authorize generic-object mutation through the existing authenticated X1
  identity and audit every change.
- Do not include policy contents or target material in routine logs.
- Ensure a malicious object update cannot cause unbounded recompilation or
  packet-path CPU use.
- Fail closed on unknown semantics while keeping unrelated tasks operational.

## 9. Test and verification matrix

### 9.1 Schema and wire tests

- Validate official V1.23.1 examples and locally constructed policy fixtures
  against the vendored XSD set.
- Round-trip every supported generic-object request and response.
- Verify namespaces, `xsi:type`, abstract generic-object decoding, UUIDs,
  dictionary entries, and ordered references.
- Confirm V1.13.1 through V1.22.1 behavior remains unchanged.

### 9.2 Validation tests

- Missing policy, missing rule, wrong object type, duplicate ID, invalid order,
  duplicate order, unsupported action, unsupported criterion, and unknown
  dictionary entry all fail before mutation.
- Multiple members of an XSD choice fail rather than selecting one.
- Task-level and mediation-level override rules are exercised explicitly.
- Unsupported V1.23.1 features never disappear silently during decoding.

### 9.3 Evaluator tests

- Every supported criterion alone and in valid combinations.
- Ordered matching and default/no-match behavior.
- `Delivered` and `NotDelivered` actions.
- One event matching multiple tasks with different results.
- One XID with multiple mediation contexts and different results.
- IRI suppression does not suppress X3.
- Suppressed events have the correct correlation, sequencing, and session-state
  effects.

### 9.4 Lifecycle tests

- Object create/modify/delete/get/list and retry behavior.
- In-use deletion and shared-rule modification.
- Atomic rollback on compile, storage, filter, and persistence failure.
- Concurrent packet evaluation with object and task mutation under `-race`.
- Deactivation, expiry, and reconciliation while a policy update is in flight.

### 9.5 Restart and reconciliation tests

- Complete graph persists and restores deterministically.
- Missing or corrupt objects keep dependent tasks disarmed.
- Incomplete snapshots do not delete valid local state.
- Authoritative object removal faults or deactivates dependents safely.
- Recompiled policy generations after restart produce identical decisions.

### 9.6 Performance tests

- Evaluation cost for no policy, one policy, maximum supported policies, and
  multiple matched tasks.
- Shared-rule updates with many dependent active tasks.
- Allocation and contention benchmarks on the packet path.
- Bounds tests proving adversarial policy graphs cannot exhaust memory or CPU.

## 10. Suggested implementation sequence

1. Resolve the policy-composition semantics and publish a capability profile.
2. Vendor pinned V1.23.1/TS 103 120 schemas and make generation reproducible.
3. Add domain types, dictionary validation, canonicalization, and pure compiled
   evaluator tests.
4. Implement the generic-object registry and dependency graph.
5. Implement X1 generic-object handlers and response serialization.
6. Expand the task/mediation model without changing runtime delivery behavior.
7. Add persistence migration and reconciliation for the complete object graph.
8. Integrate immutable evaluators between per-task IRI classification and X2
   encoding/enqueue.
9. Add status, audit, fault reporting, metrics, limits, and benchmarks.
10. Run schema, unit, integration, socket-backed, restart, fuzz, and race tests.
11. Only after all gates pass, accept and declare V1.23.1.

## 11. Acceptance criteria for enabling V1.23.1

V1.23.1 support is complete only when:

1. lippycat parses and emits the pinned V1.23.1 schema without hand-waving
   unknown enforcement fields;
2. all required generic-object lifecycle operations work atomically;
3. policy and rule references are durable and referentially safe;
4. task and mediation scopes are preserved without lossy collapse;
5. ordered policy decisions are deterministic and tested against the selected
   TS 103 120 profile;
6. suppressed IRI cannot reach X2 delivery, including during updates, restart,
   and reconciliation;
7. unsupported criteria, actions, dictionaries, and object types fail at
   provisioning;
8. existing X1 V1.13.1-V1.22.1 and X2/X3 behavior does not regress;
9. the full LI race suite and end-to-end policy scenarios pass;
10. documentation states the exact TS 103 221-1, TS 103 120, and TS 103 280
    revisions and supported policy capability profile.

## 12. Conclusion

V1.23.1 is best treated as a future authorization-policy feature, not a routine
schema bump. The correct near-term posture is to keep rejecting it and finish
the V1.13.1-V1.22.1 interoperability work independently.

When selective IRI delivery becomes a requirement, implementation should begin
with policy semantics and the generic-object domain model. Changing the version
constant or adding only `ListOfIRIPolicyReferences` would create the appearance
of support while leaving the most important behavior unenforced.
