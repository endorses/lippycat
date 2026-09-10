# Email LI over X2/X3: feasibility and implementation boundary

**Date:** 2026-08-28

**Status:** Deferred research

**Decision:** Defer first-class email lawful-interception support. Email IRI over
X2 requires a service-specific mapping from normalized observations, with an
agreed target, authorization, correlation, and MDF contract. Email content over
X3 requires a new bounded stream-content architecture
and must not be implemented as a small extension of the RTP encoder.

## Executive summary

lippycat can capture, reassemble, filter, and analyze email traffic through the
`sniff email`, `hunt email`, and `tap email` command families. That capability
does not automatically make email an LI interception product.

The current LI implementation encodes SIP-derived IRI on X2 and RTP content on
X3. Normalized SMTP observations are available for monitoring and structured
logs; they have no email LI delivery mapping.

This is not yet first-class email LI:

- X1 rejects `emailAddress` and internationalized email-address targets.
- There is no dedicated email IRI event model or interoperable email encoder.
- X3 accepts RTP content only; it cannot deliver SMTP messages or attachments.

First-class X2 email IRI is feasible as a focused project. Correct X3 email CC
is a separate, materially larger project involving TCP/TLS stream ownership,
SMTP transaction framing, bounded content retention, correlation, partial-data
semantics, and fail-closed authorization.

This report refines the older
[`li-multi-protocol-expansion.md`](li-multi-protocol-expansion.md) assessment.

## 1. Current implementation

### 1.1 Email capture and analysis

The email command families provide capture-time protocol selection and filters
for SMTP, IMAP, and POP3. SMTP analysis can expose envelope identities and
selected message metadata, and optional body capture supports bounded file
analysis.

These are monitoring capabilities. They do not establish an LI task, associate
data with an XID, authorize content collection, select an MDF destination, or
encode X2/X3 PDUs.

### 1.2 Normalized SMTP observations

`internal/pkg/events` exposes SMTP observations through typed, output-neutral
events. These can support a future service-specific email IRI adapter, but event
fields do not by themselves establish an LI product or authorize delivery.
The adapter must define its projection, target evidence, transaction/session
correlation, and MDF representation independently of structured log formatting.

### 1.3 Current target limitation

The X1 schema contains email-address choices, but
`internal/pkg/li/x1/capabilities.go` rejects unsupported target choices. The
accepted identity targets are currently SIP URI, TEL URI, E.164 number, and
NAI. Address and CIDR targets are also rejected until a raw-IP correlated
IRI/CC model is implemented.

### 1.4 Current X3 limitation

The processor's X3 branch runs only when `PacketDisplay.VoIPData` identifies an
RTP packet. It uses the RTP-oriented X3 encoder and reorder buffer. No email,
generic TCP stream, MIME entity, HTTP body, file-content, or raw-packet event is
routed into that branch.

## 2. First-class email IRI over X2

### 2.1 Scope of a bounded first phase

A useful first phase would support SMTP envelope IRI only:

- accept X1 `emailAddress` and, after an explicit normalization decision,
  internationalized email-address targets;
- translate them into exact `FILTER_EMAIL_ADDRESS` filters;
- match normalized SMTP envelope identities;
- produce defined SMTP transaction IRI events; and
- define and enforce the selected service profile's metadata/content boundary.

IMAP and POP3 should not be implied by the name "email IRI." Their identities,
commands, sessions, and content-access semantics require separate event models
and tests.

### 2.2 Required design decisions

Before implementation, specify:

- case handling for local parts and domains;
- domain internationalization and Unicode normalization;
- treatment of source routes, comments, display names, and malformed addresses;
- exact versus alias or suffix matching;
- SMTP envelope identities versus RFC message-header identities;
- how multiple recipients map to target direction and correlation;
- transaction BEGIN, CONTINUE, END, failure, and partial-capture semantics;
- which standardized or deployment-specific email IRI representation the MDF
  profile requires; and
- destination capability negotiation for that representation.

The code must not acknowledge an email-target task unless every selected
destination can consume the configured email IRI profile.

### 2.3 Likely implementation areas

- `internal/pkg/li/x1/capabilities.go`: accept only explicitly supported email
  target forms.
- `internal/pkg/li/convert.go`: convert X1 email targets into internal target
  identities without lossy normalization.
- `internal/pkg/li/filters.go`: map email targets to
  `FILTER_EMAIL_ADDRESS` and preserve LI filter ownership.
- A dedicated email IRI adapter and encoder: enforce
  target matching, redaction, event typing, and destination profile.
- `internal/pkg/events`: expose any missing SMTP lifecycle fields without body
  content.
- X1 capability and integration tests: prove activation, modification,
  deactivation, persistence, reconciliation, and fail-closed rejection.
- MDF tests: decode actual PDUs and verify XID, target, direction, timestamps,
  sequence, correlation, and redacted payload.

### 2.4 Complexity assessment

Normalized SMTP analysis and shared LI transport provide reusable building
blocks. The service-specific IRI representation, target authorization, and
session correlation require explicit design and MDF interoperability testing.

## 3. Email content over X3

### 3.1 Why packet forwarding is insufficient

SMTP content is a transaction carried over a TCP stream. Individual captured
packets do not correspond reliably to messages: commands and DATA may be split
across segments, multiple messages may share one connection, and one segment
may contain parts of multiple protocol units. Retransmission and missing
segments further prevent packet-by-packet CC encoding from representing a
coherent message.

Sending every matching TCP packet as X3 would also broaden collection beyond
the selected email transaction and could include unrelated commands or messages
on a reused connection. That is not an acceptable substitute for explicit
message authorization and correlation.

### 3.2 Required content pipeline

A correct SMTP CC path needs an instance-owned, bounded stream pipeline that:

1. reassembles TCP with explicit memory and idle limits;
2. frames SMTP commands, replies, DATA, and BDAT correctly;
3. handles dot unescaping and message termination;
4. stops application parsing at STARTTLS unless decryption keys are authorized
   and available;
5. associates content with an already-authorized target and active XID before
   retaining or emitting it;
6. assigns a stable correlation identifier shared with related X2 IRI;
7. streams content to X3 without retaining an unbounded message;
8. reports truncation, gaps, late capture, and forced release explicitly;
9. defines MIME and attachment treatment; and
10. drains or reports dropped accepted content during shutdown.

The design should be generic enough to support future HTTP or file CC without
making the RTP encoder responsible for byte-stream protocols.

### 3.3 Content and privacy boundaries

Email CC may contain credentials, personal correspondence, attachments, and
multiple recipients whose authorization status differs. The implementation
must keep these boundaries fail-closed:

- `--capture-body` is an analysis control, not LI authorization.
- `--extract-files` is a local file-analysis control, not X3 authorization.
- No content may be buffered merely because a general email filter matched.
- Task deactivation or expiry must prevent queued content from being delivered
  afterward.
- A partial or ambiguous target match must not become full-session collection.
- Body, MIME, and attachment limits must be independent of log-preview limits.

### 3.4 Protocol coverage

SMTP should be the first and only initial CC protocol. IMAP and POP3 expose
retrieved server-side messages rather than SMTP submission transactions and
need different selection and correlation policies. Implicit TLS and STARTTLS
also require decryption support before application-level target matching can
continue beyond the encrypted boundary.

### 3.5 Complexity assessment

Email X3 is high complexity. Delivery transport, TLS, queues, and generic PDU
framing can be reused, but the interception unit, stream lifecycle, correlation,
content encoding, and authorization timing are new. Treating it as an encoder
addition would hide the most important correctness and over-collection risks.

## 4. Recommended staged approach

### Stage A: capability contract

- Select and document the email IRI/CC profile expected by the MDF.
- Establish whether payloads are standardized, deployment-specific, or
  proprietary.
- Add destination capability fields and reject incompatible tasks.
- Define exact X1 target normalization and matching semantics.

### Stage B: first-class SMTP IRI

- Add `emailAddress` target provisioning.
- Map targets to owned email-address filters.
- Emit and test metadata-only SMTP IRI on X2.
- Keep all bodies, headers, attachment IDs, and file content excluded.

### Stage C: bounded SMTP content service

- Introduce a generic authorized stream-content contract.
- Implement SMTP DATA/BDAT lifecycle and capture-time correlation.
- Add a non-RTP X3 encoder/profile and MDF decoder tests.
- Add cancellation, expiry, partial-stream, backpressure, restart, and race
  tests before enabling the feature by default anywhere.

### Stage D: later protocols

- Consider IMAP and POP3 independently.
- Reuse the stream-content contract for HTTP/file CC only after SMTP proves its
  ownership and authorization model.

## 5. Verification requirements

At minimum, future implementation must include:

- X1 positive and negative capability tests for every email target form;
- exact, Unicode, malformed, multi-recipient, and case-normalization tests;
- task activation/modification/deactivation and restart reconciliation tests;
- hunter-to-processor tests proving matched LI filter IDs survive forwarding;
- SMTP fragmentation, pipelining, DATA, BDAT, dot escaping, STARTTLS, timeout,
  and port-reuse corpus tests;
- PDU interoperability tests against an independently implemented decoder for
  the selected destination profile;
- X2/X3 correlation and direction tests;
- bounded memory, queue overflow, and attributable-drop tests;
- task-expiry tests proving no post-authorization content delivery;
- graceful and forced shutdown tests; and
- race and long-running leak tests.

## 6. Deferred conclusion

lippycat has normalized SMTP observations and reusable LI transport. Email IRI
requires first-class email-address targeting, an explicit email IRI destination
profile, and a service-specific adapter. That work should be considered
separately from email CC.

Email content over X3 is feasible, but only after defining an interoperable
profile and building an authorization-aware, bounded stream-content pipeline.
Until then, the product and manual should state that X3 content delivery is
limited to the implemented VoIP/RTP path and that email command support does
not imply email CC interception.
