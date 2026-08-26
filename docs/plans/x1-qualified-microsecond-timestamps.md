# X1 qualified-microsecond timestamp conformance

**Date:** 2026-08-26
**Scope:** X1 timestamp emission, schema validation, interoperability testing,
and coordinated rollout
**Standard:** ETSI TS 103 280 `QualifiedMicrosecondDateTime` as referenced by
ETSI TS 103 221-1

## 1. Objective

Ensure every X1 timestamp represented as `QualifiedMicrosecondDateTime` is
emitted with exactly six fractional digits and an explicit time-zone designator.
Restore effective schema validation only after all deployed emitters are known
to produce conforming values, so that enabling validation does not interrupt X1
operations.

The required lexical form is:

```text
YYYY-MM-DDThh:mm:ss.ffffffZ
YYYY-MM-DDThh:mm:ss.ffffff+hh:mm
YYYY-MM-DDThh:mm:ss.ffffff-hh:mm
```

The fractional component is mandatory and contains exactly six digits. Values
with no fractional component, fewer than six digits, or more than six digits
are nonconforming even when they represent a valid instant.

## 2. Required invariants

1. Every outbound `messageTimestamp` uses the qualified-microsecond form.
2. Every outbound `MediationDetails.StartTime` and
   `MediationDetails.EndTime` uses the same form when present.
3. Whole-second values are padded with `.000000`; trailing zeroes are never
   removed.
4. UTC may be represented by `Z`; non-UTC values carry an explicit numeric
   offset.
5. Conversion from higher precision truncates sub-microsecond precision
   consistently. Formatting must not unexpectedly advance a protocol time by
   rounding it into the next microsecond or second.
6. Timestamp formatting has one implementation boundary rather than separate
   format expressions at individual message-building sites.
7. A repaired validator rejects malformed timestamps on the real protocol
   path, not only when its low-level schema API is invoked directly.
8. Validation enforcement is deployed only after every affected emitter in the
   target environment has been remediated and verified.

## 3. Non-goals

- Changing task lifecycle, tombstone, provisioning, or retry semantics.
- Changing the instant represented by a timestamp beyond the defined loss of
  sub-microsecond precision.
- Changing unrelated ASN.1 time encodings or delivery-interface timestamps.
- Requiring UTC when a schema-valid numeric offset is available.
- Broadening the accepted X1 schema or protocol revision range.
- Replacing schema validation with application-specific timestamp checks.

## 4. Phase 1 — Centralize timestamp emission

Add a package-level formatter for values represented by
`schema.QualifiedMicrosecondDateTime`. The formatter should own both the Go
layout and conversion to the schema type, preventing callers from selecting a
general-purpose RFC 3339 formatter.

The fixed-width Go layout is:

```go
const qualifiedMicrosecondLayout = "2006-01-02T15:04:05.000000Z07:00"
```

Implementation tasks:

- [x] Add an unexported `formatQualifiedMicrosecondDateTime(time.Time)` helper
      in the X1 package.
- [x] Document that the fixed-width zero pattern is intentional and that
      sub-microsecond precision is truncated.
- [x] Preserve the supplied location offset rather than forcing all values to
      UTC, unless a caller already requires UTC for independent reasons.
- [x] Replace direct `time.RFC3339Nano` formatting for all X1 response message
      timestamps.
- [x] Replace direct `time.RFC3339Nano` formatting for all autonomous outbound
      X1 request timestamps.
- [x] Replace direct `time.RFC3339Nano` formatting for mediation start and end
      times returned in task details.
- [x] Search the complete X1 package for remaining construction of
      `QualifiedMicrosecondDateTime` values and route every timestamp emitter
      through the helper.
- [x] Keep parsing changes separate. Existing broad RFC 3339 parsing may remain
      temporarily for interoperability, provided schema enforcement at the
      protocol boundary is addressed explicitly in Phase 4.

## 5. Phase 2 — Add formatter and message-level regression tests

### 5.1 Formatter tests

- [ ] Test a UTC value with non-zero nanoseconds and assert exactly six
      fractional digits followed by `Z`.
- [ ] Test a whole-second UTC value and assert the `.000000Z` suffix.
- [ ] Test a value whose microsecond component ends in zeroes and assert that
      all six positions remain present.
- [ ] Test positive and negative numeric offsets.
- [ ] Test a value with sub-microsecond precision and assert the documented
      truncation behavior.
- [ ] Parse the formatted results and assert that they represent the expected
      instants to microsecond precision.

### 5.2 Wire-message tests

- [ ] Exercise every response-building path and validate the serialized XML
      against the bundled X1 and common-type schemas.
- [ ] Exercise every autonomous request-building path and validate the
      serialized XML against the same schemas.
- [ ] Cover task-detail responses with absent, whole-second, and
      sub-microsecond mediation boundaries.
- [ ] Replace tests that expect `time.RFC3339Nano` output with exact
      qualified-microsecond expectations.
- [ ] Add a source-level guard or focused test that fails if a new outbound X1
      timestamp site uses `time.RFC3339Nano` directly.

Schema validation is the authoritative conformance assertion. Regular
expressions and string-length checks may improve failure messages, but they
must not be the only tests because the base `xs:dateTime` restrictions also
apply.

## 6. Phase 3 — Remediate other protocol emitters

Every component that emits an X1 field typed as
`QualifiedMicrosecondDateTime` must be audited independently. This work may be
implemented and deployed before strict validation is restored because it
changes invalid output into schema-conforming output without narrowing what is
accepted.

- [ ] Inventory all X1 timestamp builders in each emitting component.
- [ ] Replace variable-width, millisecond-only, nanosecond, and fractionless
      encodings with one shared fixed-width microsecond formatter per codebase.
- [ ] Cover both routine request/response messages and less frequent issue,
      status, or lifecycle reports.
- [ ] Confirm unrelated timestamp encodings are not changed solely because
      they use a similar date-time representation.
- [ ] Validate representative serialized messages directly against the
      governing XSDs.
- [ ] Record the minimum remediated version of every deployed emitter for use
      by the rollout gate in Phase 5.

## 7. Phase 4 — Restore effective validation safely

Before enforcement, determine why the validation API used on the live protocol
path can accept a document that the same cached schema rejects through a
lower-level validation entry point. Diagnose the mechanism rather than adding
a second ad hoc timestamp check that leaves general schema validation
ineffective.

Implementation tasks:

- [ ] Reproduce the discrepancy with one conforming and one deliberately
      malformed X1 document using the same schema instance.
- [ ] Trace document conversion, namespace handling, schema selection, error
      propagation, and validation-mode selection through the production call
      path.
- [ ] Correct the production-path validation function so schema failures are
      returned or raised to its caller.
- [ ] Ensure callers cannot reinterpret a validation error as a successful
      response.
- [ ] Add a regression test that passes a malformed timestamp through the full
      production validation path and asserts rejection.
- [ ] Add a conforming-message test through the same path and assert success.
- [ ] Test a non-timestamp schema violation as evidence that the repair restores
      general validation rather than special-casing this defect.
- [ ] Add structured, non-sensitive diagnostics for validation failures,
      including message type and schema error category without logging full
      interception requests or responses.

The validation repair must not be deployed until the rollout prerequisites in
Phase 5 have been satisfied.

## 8. Phase 5 — Coordinated rollout

Deploy in the following order:

1. Release timestamp-emission fixes for lippycat and all other affected
   emitters.
2. Deploy those versions everywhere that communicates with the validating
   endpoint.
3. Capture representative live messages from every emitter and validate them
   directly against the governing XSDs.
4. Confirm that no unremediated or unidentified emitter remains on the target
   X1 bus.
5. Deploy the production-path validation repair.
6. Run positive and negative end-to-end validation checks immediately after
   deployment.
7. Monitor validation failures and X1 operation outcomes through an agreed
   observation window before declaring the rollout complete.

If strict validation must be introduced gradually, use an explicit observable
report-only mode followed by enforcement. Report-only mode must count and
surface failures; it must not present itself as strict validation or silently
discard errors.

Rollback of the validator may restore availability during an incident, but it
also restores acceptance of nonconforming traffic. Treat that rollback as a
temporary degraded state with an owner and a deadline, not as completion.

## 9. Verification matrix

| Case | Expected result |
|---|---|
| Six fractional digits with `Z` | Accepted |
| Six fractional digits with valid positive offset | Accepted |
| Six fractional digits with valid negative offset | Accepted |
| Whole second encoded as `.000000Z` | Accepted |
| No fractional component | Rejected |
| Three fractional digits | Rejected |
| Nine fractional digits | Rejected |
| Missing zone | Rejected |
| Invalid calendar or offset value | Rejected |
| Valid timestamp with another schema violation | Rejected |

Verification commands for lippycat:

```bash
go test -race -tags 'all li' ./internal/pkg/li/x1/...
go test -race -tags 'all li' ./internal/pkg/li/...
```

## 10. Completion criteria

- [x] No outbound X1 `QualifiedMicrosecondDateTime` value is formatted with a
      variable-width fractional component.
- [x] All affected lippycat request, response, and mediation-time paths use the
      shared formatter.
- [ ] Representative messages from every deployed emitter validate directly
      against the governing XSDs.
- [ ] The live validation path rejects deliberately malformed messages and
      accepts conforming messages.
- [ ] Strict validation is enabled only after the emitter deployment gate is
      satisfied.
- [ ] Operational monitoring distinguishes schema rejection from transport,
      authentication, and application-level failures.
- [ ] The implementation and deployment evidence is recorded with the
      released versions and test results.
