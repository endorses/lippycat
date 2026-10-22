# ETSI X1 and X2/X3 conformance fixes

**Date:** 2026-10-22

**Status:** complete; required implementation, verification, and commit finished

**Baseline:** lippycat v0.13.1 (`ecba44ce`)

**Scope:** timestamp encoding, target-identifier encoding, X1 success responses,
and focused conditional-attribute and keepalive regression coverage

## Objective and references

Correct the identified protocol deviations while preserving interoperability
during a staged migration. Deliver the fixes independently of selective IRI
policy support or an X1 revision upgrade.

Public protocol references:

- [ETSI TS 103 221-2 V1.9.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.09.01_60/ts_10322102v010901p.pdf):
  clauses 5.3.1, 5.3.10, 5.3.18, 5.3.19, 5.1, and 6.2.4.
- [ETSI TS 103 221-1 V1.22.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.22.01_60/ts_10322101v012201p.pdf):
  response semantics, target-identifier types, and XML encoding requirements for
  the currently supported revision.
- [ETSI TS 103 221-1 V1.23.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.23.01_60/ts_10322101v012301p.pdf):
  corresponding response and target-identifier clauses in the newer revision.
  This reference does not expand lippycat's accepted X1 revisions.
- Bundled schemas in `internal/pkg/li/x1/xsd/`, with the existing `xmllint`
  validation harness in `internal/pkg/li/x1/timestamp_test.go`.

This document contains repository implementation details and public protocol
requirements only. Examples and new fixtures must use synthetic data. Do not
include external review files, private paths, organization or receiver names,
deployment inventories, operational incidents, endpoints, credentials, or
captured interception data.

## Confirmed baseline and intended behavior

| Area                                    | Current behavior                                                                              | Intended behavior                                                                                            |
| --------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Timestamp attribute 9                   | Writes 12 octets; reader accepts lengths of at least 12 and rejects 8                         | Reader accepts exactly 8 or 12; optional standard 8-octet output; legacy 12-octet output remains the default |
| Matched Target Identifier, attribute 17 | SIP X2 and RTP X3 emit a bare value for single-target tasks; RADIUS X2 omits it               | Optional XML target-identifier content with correct type and escaping; existing default output is preserved  |
| Repeated conditional attributes         | Current encoders emit each type at most once; lookup helpers support first or all occurrences | Preserve behavior and add regression coverage for non-repeatable attributes                                  |
| Keepalive PDUs                          | Builders emit the expected control header and sequence attribute                              | Preserve wire behavior, sequence validation, and version rejection; optionally improve sanitized diagnostics |
| X1 success responses                    | Seven handlers use a bare base response without a concrete type or `oK`                       | Concrete response types with exactly one `AcknowledgedAndCompleted` value                                    |

## Scope and compatibility boundaries

- [x] Preserve the default 12-octet timestamp encoding and existing attribute-17
      behavior throughout this implementation.
- [x] Keep the two new encoding settings independent, validated at startup,
      and fixed for an encoder instance. Do not infer peer capabilities from a
      failed delivery or retry with a different format automatically.
- [x] Preserve immutable encoded-byte fan-out, journal records, sequence
      ownership, correlation, task authorization, expiry, and replay admission.
      No journal migration or re-encoding is needed for these fixes.
- [x] Keep existing X1 revision acceptance and declaration unchanged. Selective
      IRI policies, generic-object provisioning, and v1.23.1 support are outside
      this plan.
- [x] Leave multi-target attribute 17/18 emission, keepalive enablement defaults,
      keepalive timer changes, and acceptance of malformed peer versions outside
      this plan. Do not add speculative compatibility exceptions.

These are protocol correctness and compatibility changes. No new latency,
throughput, CPU, RSS, restart-duration, or soak acceptance targets are introduced.

## 1. Accept both timestamp layouts safely

Primary code: `internal/pkg/li/x2x3/attributes.go` and its tests.

- [x] Introduce distinct names for the standard 8-octet and legacy 12-octet
      layouts. Correct comments that currently describe the 12-octet extension
      as the encoding specified by clause 5.3.10.
- [x] Decode exactly 8 octets as unsigned 32-bit seconds followed by unsigned
      32-bit nanoseconds, both in network byte order. Convert seconds without a
      signed 32-bit intermediate so post-2038 values remain representable.
- [x] Decode exactly 12 octets using the existing legacy seconds representation.
      Reject every other length, including oversized values with trailing data.
- [x] Validate the fractional field before conversion to `time.Time`:
      `0 <= nanoseconds < 1_000_000_000`. Return an error rather than allowing
      `time.Unix` to normalize malformed input.
- [x] Cover `Timestamp.UnmarshalBinary` and `AttributeParser.ParseTimestamp`,
      including valid round trips, malformed lengths, invalid fractions, epoch,
      the signed-2038 boundary, and the maximum unsigned 32-bit seconds value.

This reader change can ship independently of new output settings.

## 2. Emit concrete X1 success responses

Primary code: `internal/pkg/li/x1/server.go`, existing schema response types,
and X1 response/schema tests.

- [x] Make `buildOKResponse` select `CreateDestinationResponse`,
      `ModifyDestinationResponse`, `RemoveDestinationResponse`, `PingResponse`,
      `ActivateTaskResponse`, `DeactivateTaskResponse`, or `ModifyTaskResponse`
      from the handler's message type.
- [x] Populate each response with the shared base metadata and
      `OK: "AcknowledgedAndCompleted"`. Preserve qualified-microsecond timestamp
      formatting, namespace, transaction ID, and existing error responses.
- [x] Reject an unknown success-response mapping explicitly. Never fall back to
      `X1ResponseMessage` or acknowledge an operation whose outcome is unknown.
      Use the existing X1 error path for protocol failures; X1-level errors are
      typed responses over HTTP 200, not HTTP status errors.
- [x] Retain synchronous completion semantics. Do not introduce asynchronous
      `Acknowledged` responses or follow-up reporting as part of this fix.
- [x] For all seven operations, exercise the production handler and response
      container, check the expected namespace-qualified `xsi:type`, and require
      exactly one `oK` containing `AcknowledgedAndCompleted`.
- [x] Validate emitted XML against the bundled supported XSD and apply the
      existing acknowledgment validator's type, metadata, and field rules.
      Retain negative coverage for missing type, missing/duplicate `oK`, and an
      unknown mapping. Schema validity alone must not satisfy the success test.

## 3. Add explicit timestamp output selection

Proposed configuration contract:

| Surface     | Name                                    | Values                | Default     |
| ----------- | --------------------------------------- | --------------------- | ----------- |
| CLI         | `--li-delivery-timestamp-format`        | `legacy-12`, `etsi-8` | `legacy-12` |
| YAML/Viper  | `li.delivery.timestamp_format`          | Same                  | `legacy-12` |
| Environment | `LIPPYCAT_LI_DELIVERY_TIMESTAMP_FORMAT` | Same                  | `legacy-12` |

- [x] Add a validated internal format type and a fallible timestamp-building
      path. Preserve the legacy default for existing constructors/callers.
- [x] In `etsi-8` mode, require seconds in `[0, 2^32 - 1]` and nanoseconds in
      `[0, 1_000_000_000)`. Fractions within the last representable second remain
      valid. Reject negative or overflowing seconds before unsigned conversion.
- [x] Propagate timestamp errors through SIP X2, RTP X3, and RADIUS X2 encoding
      and their existing error accounting. Remove any assumption that timestamp
      marshaling errors can be ignored. Do not silently truncate, substitute a
      time, omit the timestamp, or fall back to legacy output.
- [x] Wire the setting through `cmd/process/flags_li.go`,
      `cmd/process/process.go`, `cmd/tap/flags_li.go`,
      `internal/pkg/processor/processor.go`, and encoder initialization in
      `internal/pkg/processor/processor_li.go`. Preserve non-LI stubs and builds.
- [x] Test defaults, YAML/environment overrides, explicit CLI overrides,
      unknown values, and isolation between process/tap flag bindings in an
      `all,li` build. Both commands must initialize all three encoder paths
      consistently, including RADIUS.
- [x] Keep existing legacy golden bytes and add standard 8-octet vectors for
      X2 and X3, plus RADIUS coverage. Identify legacy vectors accurately rather
      than labeling all existing bytes as standard-conforming output.
- [x] Test epoch, nonzero fractions, post-2038 seconds, maximum seconds with a
      valid fraction, and rejection immediately outside the standard range.

## 4. Serialize typed matched-target identifiers

Primary code: `internal/pkg/li/types.go`, X1 target conversion/serialization,
`internal/pkg/li/x2x3/attributes.go`,
`internal/pkg/processor/processor_li.go`, and
`internal/pkg/processor/processor_radius_li.go`.

Proposed configuration contract:

| Surface     | Name                                         | Values                      | Default |
| ----------- | -------------------------------------------- | --------------------------- | ------- |
| CLI         | `--li-delivery-matched-target-format`        | `bare`, `target-identifier` | `bare`  |
| YAML/Viper  | `li.delivery.matched_target_format`          | Same                        | `bare`  |
| Environment | `LIPPYCAT_LI_DELIVERY_MATCHED_TARGET_FORMAT` | Same                        | `bare`  |

The `bare` default names the existing SIP/RTP behavior. It does not add an
attribute to RADIUS output, where attribute 17 is currently absent.

- [x] Add one shared typed serializer that derives the X1 element from
      `TargetIdentity.Type` and `Value`. Reuse or extract the existing X1
      conversion logic where appropriate. Avoid storing raw provisioning XML
      when the existing domain type retains enough information.
- [x] Support the schema mappings `sipUri`, `telUri`, `e164Number`, `nai`,
      `ipv4Address`, `ipv6Address`, `ipv4Cidr`, `ipv6Cidr`, `imsi`, `imei`,
      `macAddress`, and `radiusAttribute`. Serializer coverage must not expand
      which target types provisioning or capture currently accepts.
- [x] Use XML serialization with proper escaping. Emit the contents of
      `TargetIdentifier` without an enclosing `targetIdentifier` element or XML
      declaration. Preserve required namespaces for structured content:
      `ipv4Cidr` contains a common-schema `IPv4CIDR` element; `ipv6Cidr` is a
      simple value in the current XSD.
- [x] Validate format-specific lexical representations, including hexadecimal
      MAC/RADIUS values and existing legacy TEL/E.164 normalization. Do not guess
      a schema type for `TargetTypeUsername`; deliberately omit optional
      attribute 17 in typed mode when no provisioned schema type is recoverable.
      Propagate unexpected serialization errors without falling back to bare XML.
- [x] In `target-identifier` mode, use the serializer for single-target SIP X2
      and RTP X3 tasks. Preserve the existing attribution and direction rules.
- [x] Apply the same opt-in format to RADIUS X2 only where one admitted target
      is unambiguous. Preserve attribute absence in default mode and preserve
      RADIUS conjunctive matching, scope, and authorization. Continue omitting
      attribute 17 for multi-target tasks in every mode.
- [x] Wire and validate the setting for process and tap using the same
      configuration precedence and command-isolation checks as timestamp format.
- [x] Test every mapping, XML metacharacters, structured CIDR namespaces,
      unsupported username behavior, and encoding errors. Validate reconstructed
      target-identifier documents against the supported schema using synthetic
      base fields. Add wire fixtures for tagged output and preserve legacy bytes.
- [x] Exercise all four combinations of timestamp and target format settings
      through SIP X2, RTP X3, and RADIUS X2. Confirm the settings are independent.

## 5. Preserve conditional-attribute and keepalive behavior

- [x] Assert at most one occurrence of each attribute type 5 through 16 in
      representative production X2, X3, and RADIUS output. Exercise configured
      optional attributes and IPv4/IPv6 endpoints so tests cover real builders.
- [x] Pin first-occurrence behavior in `FindAttribute` and preservation of all
      occurrences in `FindAllAttributes`. Do not apply a blanket deduplication
      rule to types that permit repetition.
- [x] Retain keepalive vectors and checks for zeroed fixed fields, empty
      payload, one correctly sized sequence attribute, matching acknowledgment,
      timeout behavior, and rejection of unsupported major versions.
- [x] Keep any optional invalid-version diagnostic limited to the raw numeric
      version and a fixed error category. Do not log frames, identifiers,
      destinations, provisioning messages, or payloads to diagnose a version.
- [x] Describe keepalive coverage precisely: packet-format regressions and
      existing configured operation. Do not use these tests to claim a new
      audit of all transport-profile obligations. Resolve any future question
      about duplicate sequence attributes against the standard separately.

## 6. Verify journal and rollout compatibility

- [x] Demonstrate that changing encoder configuration affects newly encoded
      product only. Queued and journaled frames must retain their original bytes
      through recovery, replay, sequence handling, and fan-out.
- [x] Cover an existing backlog followed by newly encoded product with changed
      settings, independently and together. Keep existing authorization,
      generation, expiry, and replay checks active in these tests.
- [x] Verify rollback expectations with synthetic receivers: receivers must
      accept both formats for each migrated field, including mixed replay/live
      traffic. Resetting an encoder setting does not rewrite a queued backlog.
- [x] Document migration order: release reader/X1 fixes, release opt-in output
      settings with legacy defaults, verify receiver compatibility, then enable
      standard output explicitly in a controlled deployment.
- [x] Document that receiver compatibility must cover the full lifetime of
      older queued/journaled records. Maintain legacy decoding until those
      records are no longer deliverable; longer compatibility is allowed.
- [x] Keep changing either product default as a separate follow-up change after
      explicit receiver-readiness confirmation. Implementation of this plan is
      complete without that later deployment decision or default switch.

## 7. Documentation and validation

- [x] Update `docs/LI_INTEGRATION.md`, affected command documentation, and
      configuration examples with both settings, defaults, error behavior,
      replay implications, and synthetic migration examples.
- [x] Update affected English manual pages and every language configured in
      `docs/manual/languages.json`. Translate changed catalog entries, review
      affected fuzzy entries, and run `make manual-check` and `make manual`
      when manual content changes.
- [x] Run focused unit/schema tests while implementing each change, then the
      affected integration and race suites. Require `xmllint` for authoritative
      schema tests; do not silently skip schema verification. Complete the
      project's `make test` and `make vet` checks after the focused checks pass.
- [x] Verify LI-enabled all/process/tap builds and corresponding non-LI builds.
      No dependency upgrade is required solely for this work; any newly needed
      dependency must use a verified current stable release unless compatibility
      requires otherwise.
- [x] Format changed files before staging. Record actual commands/results and
      check off only verified implementation tasks. Commit implementation and
      this updated plan together as required by the repository workflow.
- [x] Keep the plan and new fixtures free of sensitive information at final
      review. Evidence should record public protocol versions, repository test
      names, commands, and outcomes rather than private deployment details.

Suggested verification commands, to be run during implementation:

```bash
go test -tags li ./internal/pkg/li/...
go test -tags 'all,li' ./internal/pkg/processor ./cmd/process ./cmd/tap
go test -race -tags 'all,li' ./internal/pkg/li/... ./internal/pkg/processor ./cmd/process ./cmd/tap
go build -tags 'all,li' ./...
go build -tags 'processor,li' ./...
go build -tags 'tap,li' ./...
go build -tags all ./...
go build -tags processor ./...
go build -tags tap ./...
make test
make vet
```

Start tests inside the sandbox. Request permission if required tests need to run
outside it. Report unrelated failures instead of expanding this work to repair
them. Optional keepalive logging may be explicitly deferred without preventing
completion of the required fixes.

## Delivery sequence and completion record

- [x] Deliver exact dual-length timestamp parsing, typed X1 success responses,
      and the required conditional-attribute/keepalive regression coverage.
- [x] Deliver the two independent opt-in encoding settings, processor/tap
      wiring, target serialization, golden fixtures, and replay verification.
- [x] Complete affected documentation, translations, format checks, and required
      validation. Record evidence below and commit the verified work.

Implementation and verification completed on 2026-10-22. The single bounded
closure review found no remaining material issues after updating the LI-only tap
help snapshots for the two intended new flags. Required local work is closed;
implementation and the verified plan are committed together.

| Requirement                           | Evidence                                                                                                                                                                            | Result |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| Timestamp layouts and bounds          | `TestTimestampBothLayouts`, `TestTimestampRejectsMalformedWire`, `TestTimestampMarshalBounds`, all three production encoder boundary tests                                          | Passed |
| Typed X1 success responses            | Seven actual HTTP handlers, bundled-XSD validation, acknowledgment validation and negative response cases in `success_response_test.go`                                             | Passed |
| Typed target content                  | Every supported mapping and invalid-value tests in `target_identifier_test.go`, including authoritative XSD checks and qualified IPv4 CIDR content                                  | Passed |
| Independent settings and admission    | Process/tap configuration precedence, cross-command isolation, tap inheritance, constructor failure before output effects, and actual SIP/RTP/RADIUS TLS delivery in all four modes | Passed |
| Limits and error accounting           | Standard timestamp failures reach existing counters; typed expansion obeys the existing TLV bound without changing provisioning limits or falling back                              | Passed |
| Journal recovery and rollback         | Nine protocol/migration combinations in `TestWireFormatJournalMixedReplayLiveAndRollback`, with exact bytes, sequence restoration and task/destination generation checks            | Passed |
| Conditional attributes and keepalives | Real encoder cardinality tests, repeated lookup ordering, keepalive fixed fields, sequence/version checks and existing delivery regressions                                         | Passed |
| Required project checks               | `make test`, `make vet`, full affected processor/command suites, and the complete LI/processor/command race command listed above                                                    | Passed |
| Build variants                        | All six LI and non-LI build commands listed above                                                                                                                                   | Passed |
| Manual and translations               | `make manual-check` (47 regression checks; 5903/5903 current messages translated in each of Catalan and German) and `make manual` (all three editions)                              | Passed |
| Formatting and privacy                | `gofmt`, Prettier, `git diff --check`, and review of added text/fixtures for private source references or deployment details                                                        | Passed |

Optional invalid-version logging is explicitly deferred; the existing version
rejection and keepalive behavior remain covered. The manual build emitted an
existing mdBook/gettext tool-version warning, but every edition built and passed
its verification. No dependencies were added or upgraded for this work.

Legacy defaults and the existing X1 revision gate remain unchanged. Receiver
readiness and any future default switch are separate deployment/release decisions;
no deployment qualification is claimed here. Records containing sensitive
receiver or deployment details belong outside this repository.
