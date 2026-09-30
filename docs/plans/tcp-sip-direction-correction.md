# TCP SIP direction and LI payload correction

**Status:** Complete

**Source:** `/home/grischa/2026-09-28-tcp-sip-direction.md` (production
observation on v0.11.8, updated with build-time patch results and additional
defects)

## Objective

Preserve the sender of each SIP message on a bidirectional TCP connection.
Successfully parsed messages must carry the sending half's source and
destination IP addresses and ports through synthetic packet creation,
filtering, per-call SIP pcap output, `PacketDisplay`, and any X2 PDU. Keep the
two TCP halves' SIP framing independent so interleaved partial messages and a
gap in one half cannot corrupt the other.

Correct the separate `FindSIPStart` payload-selection defect so LI receives
the complete SIP message when a response contains a request-method token in
a header or body. Keep this work independently testable within the same SIP
packet-integrity change.

## Existing behavior and boundaries

- `internal/pkg/reassembly` tracks two half-connections and passes their
  `TCPFlowDirection` through `ScatterGather.Info()`. The first observed tuple,
  which may differ from the connection initiator, is the reference direction.
- `internal/pkg/voip/tcp_stream.go` discards that direction and queues both
  halves into one reader and parser. `processSipMessage` passes the fixed flow
  from `sipStreamFactory.New` to each handler.
- `internal/pkg/voip/tcp_sip_synth.go` builds a frame from the flow and
  endpoints supplied by the handler. Tap, hunter, and local/sniff TCP handlers
  share this path.
- The processor's LI conversion currently leaves `VoIPMetadata.RawSIP` empty.
  `internal/pkg/li/x2x3/FindSIPStart` searches method markers in list order
  rather than choosing the message's first valid start line. `li/sdp.go` uses
  the same fallback.
- `X2Encoder.EncodeIRI` currently suppresses all `1xx` SIP responses. This is
  an existing LI coverage gap, not a direction rule to preserve: ETSI TS
  102 232-5, clause 5.2.1 says all SIP messages executed on behalf of a target
  are subject to interception. Resolve the emission policy in separate LI
  coverage work; direction tests here still cover every synthetic packet.
- TCP SIP stream retention is complete on main (`74ed346b`, plan closure
  `8f4cfd19`). It releases retired stream references, adds tap/hunt
  `--tcp-max-streams`, and reserves capacity during rearm under the factory
  lifecycle lock. This branch started from `8f4cfd19` and preserves that
  limit and shutdown contract. `MaxStreams` now counts admitted TCP
  connections, with both direction readers sharing one slot.
- The revised source note also describes a CRLF keepalive rearm loss. This
  plan covers it because the per-half reader change must preserve rearm.
- The source note's teardown-remnant defect remains after the completed
  retention work. A final ACK or trailing RST can create a stale connection,
  and a new SYN on the same 4-tuple can be dropped. Track this as a separate
  reassembly correctness fix with real-assembler close/reopen tests, including
  missed teardown and a handshake delayed behind SIP-lane data. A new SYN
  without payload must still be allowed to create a connection.
- The failed ADMF startup sync retry is a separate LI authorization and
  availability issue. It does not change TCP SIP message direction or payload
  extraction and needs its own implementation scope.
- Build-time v0.11.8 patches provide deployment evidence for direction and
  payload correction, but the upstream code and this plan remain open. The
  final-ACK teardown patch has not yet been verified in production.

## Implementation

### 1. Carry the TCP half through SIP framing

- [x] Bring this worktree onto main at or after `8f4cfd19` before changing
      stream lifecycle code. Review the retention changes to pool removal,
      factory admission, `lifecycleMu`, and rearm against this plan.
- [x] Introduce direction-specific state under each `bufferedSIPStream` for
      queued chunks, pending gaps, reader/parser buffers, overflow recovery,
      non-SIP scanning, and discard state. Use `sg.Info()` to route each
      `ReassembledSG` delivery to its half without blocking the assembler.
- [x] Preserve the existing bounded SIP framing, `Content-Length` validation,
      resynchronization, keepalive handling, timestamps, and non-blocking queue
      behavior independently for each half. A timeout, malformed message, or
      reassembly gap in one half must not reset the other half's parser.
- [x] Pass the original network/transport flows and endpoint strings for the
      first-observed half. Reverse both flows and swap endpoints for the other
      half before parsing and handler dispatch. Use the actual sending half
      rather than SIP request/response role to choose direction.
- [x] Coordinate connection-level shutdown, `ReassemblyComplete`, 4-tuple
      rearm, call-ID detection, TCP buffered-packet cleanup, worker counting,
      and factory shutdown with the two half states. Prevent a worker from
      closing shared state still used by the other half.
- [x] Make the finished-half rearm gate recognize a SIP start line after
      bounded leading CRLF keepalives, consistent with the live parser. Keep
      keepalive-only chunks from starting a worker, and count them separately
      from rejected data chunks. Preserve the request when CRLF and the next
      SIP message arrive in one reassembled chunk.
- [x] Define the `MaxStreams` admission unit before adding workers. Preserve
      main's atomic slot reservation and shutdown exclusion for both halves,
      including rearm; reject a connection or reserve its required capacity
      as one atomic decision so only one half is never admitted by accident.
      Update the limit's wording if its unit changes. Keep zero as unlimited.

### 2. Preserve SIP bytes in LI output

- [x] In the processor SIP-to-`PacketDisplay` conversion, populate `RawSIP`
      from the decoded transport payload when it contains a complete SIP
      message, including the synthetic TCP packet path. Keep payload bytes
      bounded to the message and do not treat IP/TCP headers as SIP content.
- [x] Harden `FindSIPStart` for remaining fallback callers: choose the
      earliest syntactically valid SIP start line at a line boundary, whether
      it is a request or `SIP/2.0` response. Make `li/sdp.go` consume the same
      corrected message span.
- [x] Preserve X2's existing SIP payload-direction semantics and LI admission
      rules. Verify network attributes come from the corrected packet
      direction and payload bytes remain unchanged.

### 3. Regression coverage

- [x] Drive the real reassembly engine with one synthetic TCP connection:
      first-observed UE → P-CSCF `INVITE`, reverse-half `100`/`183`/`200`,
      then UE → P-CSCF `ACK` and `BYE`. Assert source and destination IPs and
      ports on every dispatched synthetic packet and on emitted X2 PDUs,
      especially the `200` response. Record the current lack of `1xx` X2 PDUs
      separately from the direction result.
- [x] Repeat with the response half observed first. Assert the first-observed
      tuple rule without assuming which endpoint initiated the connection.
- [x] Interleave partial messages from both halves and introduce a gap or
      queue overflow in only one half. Assert complete messages and recovery
      remain isolated by half, with no byte splicing.
- [x] Cover tap, hunter, and local/sniff handler behavior where they consume
      the common stream; include per-call SIP pcap direction and a processor
      `PacketDisplay` check.
- [x] Test close/flush, shutdown, idle retention, 4-tuple reuse/rearm,
      non-SIP discard, and configured `MaxStreams` admission with both halves
      active. Check worker counts return to zero and no channel is closed
      while a producer can still send.
- [x] Test a finished half receiving `\r\n\r\nINVITE` in one chunk and a
      keepalive-only chunk followed by an INVITE chunk. Assert no request is
      lost and keepalive-only traffic does not inflate rejection counts.
- [x] Test `FindSIPStart`, X2 payload, and SDP extraction using a response
      whose header or body contains `INVITE `, plus normal requests and
      responses. Verify the entire response starts at `SIP/2.0`.

## Verification and completion

- [x] Run focused VoIP and reassembly tests, LI tests with the `li` build tag,
      and affected tap, hunt, and sniff tests under their build tags. Run race
      tests for half-stream dispatch, close/flush, and rearm. Build the affected
      specialized variants with and without LI.
- [x] Use a synthetic pcap to confirm the per-call SIP pcap and X2 attributes
      show opposite addresses for the two halves while the SIP payload remains
      intact. Record the test command and result; production data is not
      required.
- [x] Format changed files, review the diff, mark only verified tasks above
      complete, and commit the implementation and this plan together.

## Verification record

| Check | Result |
| --- | --- |
| `go test -race -tags all ./internal/pkg/voip -count=1` | Passed, including split rearm, long start line, gap, overflow, reverse-first, and lifecycle regressions. |
| `go test -tags 'all li' ./internal/pkg/voip -run TestTCPDirectionRealReassemblyCarriesSenderToX2 -count=1` and `go test -tags all ./internal/pkg/voip -run TestTCPLocalPath_BidirectionalSIPPCAPUsesSenderAddresses -count=1` | Passed, as did a combined race run. The synthetic connection produced opposite 5-tuples in per-call PCAP and X2 attributes; all six SIP payloads remained intact. Current `1xx` X2 suppression is tracked separately. |
| `go test -tags 'all li' ./internal/pkg/li/x2x3 -count=1` and focused LI SDP tests | Passed, including earliest valid SIP start, bounded fallback scan, malformed framing, and response payload. |
| `go test -tags 'all li' ./internal/pkg/processor -count=1` outside the sandbox, plus the focused processor direction test | Passed. The unrestricted run was needed for local socket and securestore fixtures. |
| `go test -tags tap ./cmd/tap -count=1`, `go test -tags 'tap li' ./cmd/tap -count=1`, `go test -tags hunter ./cmd/hunt -count=1`, `go test -tags cli ./cmd/sniff -count=1`, `go test ./internal/pkg/reassembly -count=1` | Passed. |
| `go build` with tags `tap`, `tap li`, `processor`, `processor li`, `hunter`, and `cli` | Passed for every variant. |

The bounded closure audit found and resolved split pre-rearm starts, a
cross-direction local PCAP timestamp fallback, a quadratic LI fallback scan,
and an initial rearm probe shorter than the parser's valid start-line bound.
The terminal decision is **CLOSED**.
