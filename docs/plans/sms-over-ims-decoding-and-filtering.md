# SMS-over-IMS Decoding, Metadata, and Optional Filtering

**Date:** 2026-10-24

**Status:** Complete. Implementation, validation, and task cleanup are committed together.

## Objective and agreed behavior

Decode SMS-over-IMS once through a reusable Go package, carry the result in
structured protobuf metadata, and show readable message content in VoIP call
details. Hunters and taps can optionally match keywords in decoded SMS text.

Decoding and display do not require keyword filtering. With no SMS keywords
configured, preserve existing capture, selection, forwarding, and PCAP behavior,
including existing SIP identity filters and signalling/media policies. An SMS
keyword match only narrows traffic already eligible under those policies; it
never grants capture authority or enables media capture.

The implementation supports incoming and outgoing text SMS, GSM7 and UCS2,
correct user-data-header handling, multipart joining, and keyword matching across
segment boundaries. Display incomplete multipart messages explicitly while parts
are arriving; show the complete text when all compatible parts are present.

Reuse existing SIP/TCP framing, call-lifecycle, and bounded-buffering patterns.
TCP reassembly reconstructs one SIP message from network segments; INVITE dialog
tracking associates separate SIP exchanges. SMS concatenation associates separate
MESSAGE transactions using their SMS headers and requires its own assembly key,
which may span Call-IDs and transport connections.

This plan introduces no latency, throughput, CPU, RSS, or soak acceptance target.
Preserve existing authorization, expiry, durability, and configured resource
limits. Measurements may inform implementation but do not create new gates.

## Current implementation and integration points

| Area               | Existing behavior and intended change                                                                                                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shared SIP parsing | `internal/pkg/sip/parser.go` exposes binary `SIPEvent.Body` and `ContentType`; `internal/pkg/pipeline/sip_result.go` preserves them. Reuse these contracts.                                                                  |
| Hunter UDP         | `internal/pkg/voip/udp_handler_hunter.go` handles parsed SIP and selection. Attach decoded SMS and enforce the optional predicate before output.                                                                             |
| Hunter TCP         | `internal/pkg/voip/tcp_handler_hunter.go` processes each complete SIP message and synthesizes its own packet. Decode once per message, not once per TCP connection.                                                          |
| Tap                | `internal/pkg/voip/tcp_handler_tap.go`, `internal/pkg/voip/processor/sipflow.go`, and processor source policy paths handle complete messages. Use the same decoder and filtering semantics without introducing gRPC locally. |
| Local/offline TUI  | `internal/pkg/tui/tcp_handler_tui.go` receives complete SIP results; `offline_sip.go` feeds that path. Preserve SMS through `VoIPMetadata` and local call aggregation.                                                       |
| Remote TUI         | `internal/pkg/remotecapture/client_conversion.go` preserves raw packet bytes but aggregates calls from SIP protobuf metadata. Consume the new structured field.                                                              |
| Call details       | `AggregatedCall`, `types.CallInfo`, and `components.Call` need SMS data; call-store replacement and response updates must preserve it.                                                                                       |
| Keyword matching   | `internal/pkg/email/content_filter.go` demonstrates case-insensitive Aho-Corasick matching. Reuse the matcher package, without coupling SMS to email types.                                                                  |

Raw SIP can already be sufficient for decoding. In particular, current hunter/tap
TCP forwarding can carry a synthesized packet with the complete reassembled
message. The protobuf extension provides one interpretation to all consumers; it
is not justified by assuming every remote TCP packet is necessarily incomplete.
Validate normalized forwarding, raw/truncated input, and older-peer behavior.

## 1. Define the decoder and message contract

- [x] Add `internal/pkg/sms` as a protocol library independent of Cobra, Viper,
      protobuf, SIP framing, filtering, and TUI code. Accept binary RPDU bytes;
      return an owned typed result and explicit errors/statuses. Keep stateless
      decoding separate from any transaction-retention state.
- [x] Define RP message type, TP message type, direction, alphabet/coding,
      decoded text, original DCS, SMS addresses, and optional concatenation
      metadata. Preserve absent/unknown values. TPDU addresses are distinct from
      SIP routing identities; do not invent a missing party from a proxy URI.
- [x] Distinguish successful empty text from unsupported coding, malformed or
      incomplete input, and recognized control/report messages. A control
      message must not appear as a successfully decoded user text message.
- [x] Parse RP-DATA in both directions, including reference, variable-length
      address fields, and RP user data. Recognize RP-ACK, RP-ERROR, and RP-SMMA
      without interpreting their bytes as user text.
- [x] Parse SMS-SUBMIT and SMS-DELIVER TPDU layouts, including numeric and
      alphanumeric addresses, PID/DCS, timestamps where present, and all
      SMS-SUBMIT validity-period layouts needed to locate the user data safely.
      Recognize unsupported TPDU report/command types explicitly.
- [x] Decode GSM 7-bit packing, the default alphabet, and extension escapes;
      respect TP-UDL rather than deriving text length from all available bits.
      Decode UCS2 in big-endian order with an explicit policy for malformed
      code units; produce valid UTF-8 without silently claiming exact decoding
      after a decoding error.
- [x] Parse bounded UDH information elements, skip unknown well-formed elements,
      and account for GSM7 header septets and fill bits. Extract 8-bit and
      16-bit concatenation references, segment count, and segment position.
      Validate UDH lengths and segment ranges before exposing them.
- [x] Report unsupported 8-bit binary, compressed payloads, and national-language
      shift tables explicitly in this initial scope. Do not silently decode
      them using the wrong alphabet. Treat odd UCS2 lengths, truncated escape
      sequences, inconsistent lengths, and reserved coding groups deliberately.
- [x] Check every read and length calculation. Bound work and allocations by
      the actual input and applicable protocol limits; do not allocate from an
      unvalidated length. Keep raw bytes out of text error messages and logs.

## 2. Assemble multipart SMS through a reusable component

- [x] Add a stateful assembler alongside the stateless decoder in
      `internal/pkg/sms`, with explicit configuration, clock/expiry, ownership,
      reset, and shutdown contracts. Reuse existing bounded retention and
      lifecycle patterns without forcing SMS assemblies into INVITE dialog or
      Call-ID-only registries. Keep SIP packet retention in adapters outside the
      protocol library.
- [x] Group segments by capture session/observation scope, direction, known SMS
      parties, concatenation reference and width, total parts, and compatible
      coding/header information. Exclude SIP Call-ID and TCP connection as
      mandatory grouping keys. Distinguish subscriber/source contexts and
      ambiguous identities; do not merge solely on a short reference number.
- [x] Accept out-of-order segments and expose pending, complete, conflicting,
      expired, and resource-limited outcomes with received/missing positions.
      Identical retransmissions do not duplicate text or extend retention
      indefinitely. Conflicting content for one position must not overwrite a
      validated assembly silently or create an apparently complete message.
- [x] Join text in declared segment order after correct per-segment UDH removal
      and alphabet decoding. Packed GSM7 octets cannot simply be concatenated:
      each segment has its own header/fill-bit alignment. Preserve exact text
      across joins and distinguish partial previews from complete text.
- [x] Bound assembly count, retained bytes, segments, and assembly lifetime.
      Account for completed-result/deduplication state as well as pending parts.
      Define deterministic expiry and reference-reuse behavior using capture
      timestamps for offline processing and existing live-clock patterns.
      Release state on eviction, expiry, capture replacement, reset, and shutdown.
- [x] Make assembly available with keyword filtering disabled, without delaying
      existing packet forwarding or PCAP writing. Only enabled filtering needs
      to retain eligible contributing SIP packets pending the complete decision.
      Preserve partial display after missing/conflicting/expired parts without
      presenting it as a successfully assembled full message.

## 3. Add structured protobuf metadata and adapters

- [x] Add an additive `SMSMetadata sms` field to `SIPMetadata` in
      `api/proto/data.proto`, using an unused field number verified at
      implementation time. Define a nested record rather than only `sms_text`.
- [x] Include decoded text, DCS/encoding, decode status, RP/TP types, direction,
      SMS addresses, and optional concatenation metadata. Use unspecified enum
      zero values and presence where absence matters. A missing SMS record
      means metadata was not supplied, not that decoding failed or text was
      empty. Use bounded status codes, not arbitrary payload-bearing errors.
- [x] Preserve per-segment text and identity even when a complete assembly is
      available. Carry assembly status and optional complete assembled text,
      including received/missing-position information as appropriate, so the
      completing update can deliver the full result without rewriting original
      SIP packets. Scope grouping information to preserved capture provenance;
      downstream consumers must not merge unrelated capture sources.
- [x] Store decoded, valid UTF-8 text in string fields. Retain the original body
      in existing packet/raw-SIP bytes; do not duplicate it into a protobuf
      string. Decode status must distinguish binary/unsupported data.
- [x] Map between the SMS domain result and protobuf at pipeline boundaries.
      Propagate the result through packet metadata adapters, metadata cloning,
      normalization, processor enrichment, upstream forwarding, and fan-out.
      Keep protobuf imports out of the decoder.
- [x] Regenerate bindings using `api/proto/Makefile`; do not edit generated Go
      files manually. Use current stable compatible tooling and inspect the
      generated diff for unrelated changes; dependency upgrades are not a
      prerequisite unless compatibility requires them.
- [x] Add wire round-trip and absent-field compatibility tests. Older receivers
      may ignore the new field; newer receivers must tolerate its absence.
      Preserve metadata across processor hierarchies and tap source conversion.

## 4. Decode and assemble at complete-message ingestion

- [x] Identify SMS by parsed MIME media type `application/vnd.3gpp.sms`, allowing
      parameters and case variations. Ordinary `text/plain` SIP MESSAGE and
      unrelated SIP bodies are outside the SMS keyword predicate.
- [x] Decode after existing transport reassembly and SIP framing, before optional
      content matching. Share the enrichment step across UDP and TCP adapters
      and reuse an already decoded result. Never trim binary bodies or parse
      the body as a NUL-terminated string.
- [x] Wire hunter, tap, processor-local input, and local/offline TUI paths to the
      same decoder. Cover coalesced SIP messages and repeated messages on a
      long-lived TCP connection independently. Reuse existing ESP-NULL and
      fragmented-packet normalization rather than adding SMS-specific versions.
- [x] Run assembly after segment decoding. Reuse supplied complete assembly
      metadata downstream; assemble observed segments through the same library
      when completion metadata is unavailable. Preserve per-segment records and
      avoid duplicate completed-message updates across enrichment and fan-out.
- [x] Prefer supplied SMS metadata downstream. Where metadata is absent and a
      complete eligible SIP message is available, allow shared-parser/decoder
      enrichment without a separate TUI decoder. Truncated or unavailable bodies
      remain unavailable; do not add a second remote TCP assembler for this
      feature or claim ciphertext can be decoded.
- [x] Ensure malformed or unsupported SMS does not discard otherwise eligible
      traffic while keyword filtering is disabled. Preserve raw packet access
      and expose decoding status without changing unrelated protocol behavior.
- [x] Keep content-bearing metadata inside existing authorized content paths.
      Audit LI metadata copying so new SMS text cannot bypass IRI-only body
      restrictions. Do not add SMS text to logs, metrics, status output, or
      structured protocol streams as an incidental side effect.

## 5. Implement optional hunter/tap keyword filtering

- [x] Add `--sms-keywords` and `--sms-keywords-file` to `hunt voip` and `tap voip`,
      with documented role-specific Viper keys and normal flag/config/env
      precedence. Both default empty. An absent or empty configured pattern set
      disables filtering and allocates no SMS transaction-decision cache.
      Reject unreadable files and invalid configuration with contextual errors.
- [x] Implement a separate SMS content matcher over decoded text, using the
      existing Aho-Corasick package. Define case-insensitive literal substring
      matching, OR between keywords and between the two keyword sources, and
      consistent normalization of patterns and text. Preserve original display
      text; regex, stemming, and accent folding are outside this scope.
- [x] Apply the predicate as an additional AND condition to eligible SMS
      transactions. Ordinary calls, RTP, and non-SMS pager messages keep their
      existing behavior. A keyword match cannot create SIP-user selection proof,
      promote media endpoints, or override capture/authorization restrictions.
- [x] Enforce the gate across default and non-default policy paths, before
      forwarding, selected-output PCAP writing, or broadcast. Do not implement
      it solely as `sipflow.Message.Match`: direct matches and sticky Call-ID
      selection can bypass that callback. `signalling-policy=all` must not
      override an explicitly enabled SMS predicate; `none` stays absolute.
- [x] With filtering enabled, only successfully decoded matching text admits
      the SMS transaction or multipart group. Multipart text remains pending
      until all valid compatible parts arrive; evaluate keywords on the joined
      text, including matches spanning segment boundaries. Nonmatching,
      malformed, unsupported, expired, or conflicting text does not match.
      Classify control/report messages separately and
      retain only those that can be associated with an admitted SMS exchange;
      unrelated reports do not gain admission from an old Call-ID match.
- [x] Track keyword decisions by capture/session/domain, source, SIP transaction
      identity, and direction, not solely Call-ID or TCP connection. Include
      CSeq and available branch identity; avoid conflating requests with later
      unrelated MESSAGE transactions. Treat retransmissions idempotently and
      reject conflicting identity reuse rather than borrowing an old match.
- [x] Preserve SIP responses and associated control exchanges for admitted SMS
      without requiring a text match on their empty/control bodies. Define and
      test bounded pending handling for response-before-request ordering and
      ambiguous association. Never interpret a SIP 200/202 alone as proof that
      SMS user content was decoded or delivered to the handset.
- [x] Use bounded count/byte retention and expiry for pending responses and
      decisions, integrating existing limits where suitable. Add explicit
      configuration only for genuinely new retained resources. Expiry,
      overflow, reset, shutdown, and capture replacement release all retained
      references; they cannot admit unmatched SMS or affect disabled filtering.
- [x] With filtering enabled, retain eligible contributing SIP messages and
      associated transaction responses under count/byte/lifetime limits until
      assembly completes. On a match release all contributing eligible messages
      once, preserving original packet provenance and timestamps. On nonmatch,
      expiry, conflict, or resource exhaustion release retained references and
      record the reason without content. Do not forward an early segment merely
      because its partial text contains a keyword.
- [x] Preserve the baseline selection decision and policy generation for each
      retained contributor and revalidate at release. An assembly or matching
      segment cannot authorize a part rejected by identity/capture policy, borrow
      authority from a different source, or admit later messages reusing its
      concatenation reference. Disabled filtering retains no packets for keyword
      decisions, even while text assembly remains active for display.
- [x] Verify per-message TCP synthesis and UDP framing cannot release a second
      rejected SMS through a selected message's raw packet or whole-flow drain.
      Preserve existing packet provenance and checksum/timestamp behavior.

## 6. Show decoded SMS in call details

- [x] Carry SMS records through `VoIPMetadata`, `AggregatedCall`, `CallInfo`,
      local call notifications, remote conversion, `components.Call`, call-store
      replacement, copies, and offline indexing/loading. Preserve ownership and
      concurrency guarantees when adding slices or pointers.
- [x] Retain a bounded per-call collection keyed by SMS transaction identity so
      Call-ID reuse for multiple MESSAGE transactions does not silently replace
      earlier content. Suppress retransmission duplicates; response-only and
      control updates must not erase a previously decoded message.
- [x] Add a Message section in `renderCallDetailsContent`, showing text,
      encoding, decode status when needed, SMS parties where known, and
      multipart position/reference and assembly progress. Show joined text when
      complete and clearly label incomplete text/missing segments. Associate
      updates across contributing call entries even when parts use different
      Call-IDs, without merging unrelated call or media state.
      Keep SIP identities separately labelled.
      Preserve existing terminal SMS state/duration behavior and ordinary call
      details.
- [x] Escape terminal control sequences, wrap by terminal-cell width, and support
      narrow panes, multiline text, Unicode, scrolling, and text selection.
      Show explicit unavailable/unsupported/malformed status with bounded
      diagnostic information and existing raw-packet access instead of garbage.
- [x] Ensure decoded content survives packet-ring eviction while its call is
      retained, subject to bounded call/message storage. Clear/reset and call
      eviction release content; metadata absence from an older peer must not
      erase an already available result.

## 7. Validate behavior and document the feature

- [x] Add synthetic, independently checked fixtures for MO/MT RP-DATA and
      SUBMIT/DELIVER, GSM7 extension characters, UCS2, empty text, address
      variants, validity periods, UDH fill-bit offsets, both concatenation
      reference widths, and recognized control/report types. Cross-check
      expected decoded output with a separate known decoder where available;
      do not derive expected values solely from the code under test.
- [x] Add fuzz and malformed-input coverage for RP/TPDU length fields, UDH
      elements, DCS groups, escapes, invalid code units, and truncation. Test
      stable error classification and no panics or oversized allocation.
- [x] Exercise assembly of both reference widths, GSM7 with different fill-bit
      offsets, UCS2, out-of-order parts, missing parts, exact/conflicting
      duplicates, reference reuse, source/domain separation, and segments spread
      across Call-IDs or transport connections. Verify assembly expiry, byte/count
      limits, reset/shutdown, and bounded completed-result retention.
- [x] Extend UDP/TCP hunter/tap fixtures, including existing IMS MESSAGE tests
      in `tcp_handler_tap_test.go`, capture-policy tests, and processor SIP-flow
      equivalence tests. Exercise split TCP messages, coalescing, multiple SMS
      on one connection, retransmission, response-first capture, domain/session
      separation, and reused Call-IDs with opposing keyword results.
- [x] Verify disabled filtering preserves baseline outputs for matching,
      nonmatching, malformed, and unsupported SMS. Verify enabled filtering
      cannot be bypassed by existing direct/sticky selection or signalling-all;
      also verify signalling-none and unrelated call/RTP behavior.
- [x] Test keyword sources and configuration precedence, matching normalization,
      no-keyword mode, unsupported/binary inputs, retention exhaustion/expiry,
      and cross-segment matches. Verify full-group release once on match and no
      early/partial release on a pending, failed, or nonmatching group; verify
      disabled filtering forwards normally while assembly proceeds for display.
      Keep packet loss distinguishable
      from a negative keyword result without logging message contents.
- [x] Test protobuf propagation, mixed peer versions, tap-to-processor and
      hunter-to-processor-to-TUI delivery, local live/offline display, call-store
      replacement, packet eviction, and terminal-control sanitization. Use
      synthetic captures with no real subscriber identities or message bodies.
- [x] Run focused tests for the changed packages, race checks for shared state,
      `make test`, and `make vet`. Build all affected role variants, including
      hunter, tap, processor, TUI, and relevant LI combinations. Use project
      build/test tags; untagged `go test ./...` is not the full test entry point.
      Ask before running tests outside the sandbox if required.
- [x] Update command help, affected README/configuration documentation, and
      `docs/research/sms-message-handling-in-tui.md` to describe implemented
      behavior. Update affected manual chapters and every language configured
      in `docs/manual/languages.json`, review changed fuzzy entries, and run
      `make manual-check` and `make manual` when manual content changes.
- [x] Format changed source and documentation, review generated bindings and
      diffs, and record actual validation results. Check off tasks only after
      verifying them. Commit implementation and the updated plan together;
      remove temporary test, generation, and formatter caches created for the
      task.

## Verification evidence (2026-10-24)

`make test` passed both the complete `all` suite and the LI package suite.
The full test entry point ran outside the sandbox after an approved targeted run
confirmed that the sandbox's UID mapping of `/` and `/tmp` caused unrelated
securestore ownership checks to fail. No securestore behavior was changed.

`make vet` passed. Hunter, tap, processor, TUI, all, tap+LI, processor+LI, and
all+LI binaries built successfully. Focused race checks passed for the SMS
library/controller, source/configuration, hunter output, shared types,
local/remote TUI, and call aggregation. Decoder fuzzing completed 148,529
executions without failure. Wire tests cover absent metadata, older readers,
unknown-field relay, and processor/tap forwarding reconstruction.

Production-path regressions cover complete-message UDP/TCP handling, joined
keywords across different Call-IDs and mapped interfaces, domain separation,
response/control correlation, original inherited and direct selection proofs,
producer-seal revalidation, and rejection of inseparable trailing UDP content.
TUI tests cover compact/oracle offline storage, split/coalesced TCP and UDP,
response-only replacement, idle-live versus capture-clock expiry, retained call
text, and source-scoped multipart updates. LI snapshot coverage verifies that
presentation SMS content is not retained in the authorized LI correlation copy.

`make manual-check` and `make manual` passed with the new content translated in
Catalan and German. The installed gettext preprocessor emits a preexisting
mdBook version warning; all editions and cross-edition checks still pass.
Changed Go files pass `gofmt`, Markdown passes Prettier, and whitespace checks
pass. External encrypted traffic and deferred coding/report features remain
outside the explicitly described protocol subset.

The bounded final review identified two additional display defects: producer
negative assembly outcomes were overwritten locally, and known-domain interfaces
split display identities. Both were repaired in one supplemental batch. Exact
shared-adapter, local, and remote regressions and affected SMS race checks pass;
producer failure states remain authoritative and mapped interfaces now share
completion updates without merging distinct domains. No further review campaign
or additional product gates were introduced. The final full test suite, vet, and
eight role builds also pass with both supplemental fixes included. The bounded
closure audit is closed; no required implementation work remains.

## Deferred scope

National-language shift tables, compressed SMS, application-specific binary SMS,
full delivery-report correlation, new SMS log streams, new LI export formats,
new standalone SMS commands, and remotely managed SMS filter types are outside
this implementation. Existing LI authorization and content restrictions remain
required regression coverage, not deferred work.

## References

[Historical TUI analysis](../research/sms-message-handling-in-tui.md) records the
earlier SMS state fix and the original decoder/display proposal.

[3GPP TS 24.341](https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/08.03.00_60/ts_124341v080300p.pdf)
describes SMS transport in SIP MESSAGE;
[TS 24.011](https://www.etsi.org/deliver/etsi_ts/124000_124099/124011/18.00.00_60/ts_124011v180000p.pdf)
defines the RP layer;
[TS 23.040](https://www.etsi.org/deliver/etsi_ts/123000_123099/123040/18.00.00_60/ts_123040v180000p.pdf)
defines TPDU layouts and user-data headers; and
[TS 23.038](https://www.etsi.org/deliver/etsi_ts/123000_123099/123038/18.00.00_60/ts_123038v180000p.pdf)
defines alphabets, packing, and coding schemes. These are references for the
implemented protocol subset, not a claim of full SMS specification coverage.
