# SIP LI coverage, TCP tuple reuse, and ADMF recovery implementation review

Implementation baseline: `a42514e3`. Scope is the three workstreams in
[the remediation plan](sip-li-and-tcp-reuse-remediation.md). The earlier direction
and retention fixes remain in place; this implementation adds no numerical
performance acceptance gate.

## SIP product and authorization

Complete admitted SIP messages now use Payload Format 9 regardless of request
method or response class. Extension methods follow RFC token grammar in parsing
and detection. The processor validates transport framing and raw Call-ID before
using SIP metadata for LI. Invalid framing cannot recover a later SIP-looking
substring through encoder fallback. Task/filter, generation, delivery-type, and
destination admissions still precede delivery.

`X2Only` selects an explicit conservative policy: retain SDP signaling and
withhold other bodies, including SMS MESSAGE, extension requests, multipart, and
response bodies. Length headers are rewritten while preserving parseable SIP;
`X2andX3` preserves the captured message. This local policy does not claim SMS
TPDU rewriting or HI2 ASN.1 compliance. See the operator guide for that boundary.

Encoder and TLS MDF processor tests cover 100/180/183, redirects, SERVICE,
MESSAGE, existing success/failure responses, malformed and unauthorized input,
payload bytes, addresses, correlation, sequences, and delivery-type restrictions.

## TCP lifetime and ordering

Unmatched control-only packets without SYN cannot create a connection or SIP
workers. New opening SYNs replace stale generations; retransmissions and
correlated delayed SYNs preserve their stream. Replacement holds the connection
lock and pool pin, releases queued/retained pages, completes the old stream once,
and leaves slab recycling to the final pin release. A SYN recorded on a rejected
stream permits later replacement once admission capacity becomes available.

Capture buffers track regular-lane predecessors per TCP tuple. SIP packets from
that tuple remain ordered behind predecessors; other flows retain SIP priority.
The added map holds counters, with cardinality bounded by queued packets and
active senders. Existing channel capacities, assembler page limits, and factory
`MaxStreams` enforcement remain authoritative. At the configured stream cap,
replacement can be rejected until the old workers finish draining; admission is
not relaxed to permit overlapping workers beyond the limit.

Real assembler and SIP-worker regressions cover both tuple orientations,
trailing RST/duplicate FIN/final ACK, missed FINs, half-close, reverse-first passive
capture, SYN retransmission, delayed SYN, idle flush, retained pages, concurrent
replacement, cap recovery, and worker shutdown. Capture tests queue handshake
and SIP data deterministically and exercise the production merger and assembler.

## ADMF authority and recovery

Startup synchronization publishes pending, retryable failure, unsupported, or
succeeded state. Timeout/request failures and entry conversion/application
failures stay pending. Retries use a fresh configured attempt timeout and bounded
backoff independently of periodic reconciliation. Snapshot application is
serialized with X1 mutations; periodic recovery attempts coalesce after success.
Stop cancels requests/backoff and joins workers. Replay confirmation has its own
reader/writer lock because recovery can now finish after Start returns.

The shared client rejects wrong response types, incomplete required sections,
and empty/multiple-message envelopes before any state application. Present empty
lists remain valid. Persisted active tasks remain candidates until their task and
destinations are confirmed. Partial snapshots preserve possible orphans; exact
filters for known refused tasks without a live owner are withdrawn. Repeated
equivalent snapshots preserve generations, filters, and destination queues.

Manager status exposes attempt count, last failure category, last attempt, and
recovery time. Recovery telemetry withholds remote descriptions/response bodies
that could contain target definitions. Unsupported operation is terminal for both
standard code 1080 and legacy code 7.

The separate startup notification retains bounded client retries. Retried NE
reports use a new transaction UUID with unchanged issue content, as permitted by
[ETSI TS 103 221-1 V1.22.1 clause
5.2.3](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.22.01_60/ts_10322101v012201p.pdf).
The specification does not require indefinite startup-notification retries.
The existing `Startup` notification extension and HTTP success acknowledgment
behavior remain outside this remediation; neither authorizes interception.

## Verification

Commands use a temporary writable Go cache where needed; tests requiring local
ADMF/MDF listeners ran outside the sandbox with approval.

| Command                                                                                                                                                                                                                                                          | Result                                                         |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `go test -tags li ./internal/pkg/li/... -count=1`                                                                                                                                                                                                                | Passed: manager, persistence, delivery, encoder, X1            |
| `go test -tags all,li ./internal/pkg/processor ./internal/pkg/li/x2x3 ./internal/pkg/sip ./internal/pkg/detector/signatures/voip -count=1`                                                                                                                       | Passed                                                         |
| `go test -race -tags li ./internal/pkg/li -run 'TestStartupSync(Retry\|Unsupported\|Partial\|Stop\|Serializes\|Entry)' -count=1`                                                                                                                                 | Passed, including malformed snapshots and persisted candidates |
| `go test -race -tags li ./internal/pkg/li/x1 -run 'TestClient_GetAllDetails\|TestClient_ReportStartup' -count=1`                                                                                                                                                 | Passed                                                         |
| `go test -race -tags all ./internal/pkg/reassembly ./internal/pkg/capture ./internal/pkg/voip -run 'TestConnection\|TestStreamPool\|TestTCPQueueOrdering\|TestPacketBuffer\|TestTCPSIP\|TestTCPDirection\|TestSipStreamFactory\|Test.*Rearm\|TestResync_Reused'` | Passed                                                         |
| `go build -tags processor .`, `processor,li`, `tap`, `tap,li`                                                                                                                                                                                                    | Passed                                                         |

The final integrated command was:

```sh
go test -tags all,li ./internal/pkg/li/... ./internal/pkg/reassembly ./internal/pkg/capture ./internal/pkg/voip ./internal/pkg/processor ./internal/pkg/sip ./internal/pkg/detector/signatures/voip -count=1
```

LI, reassembly, capture, VoIP, parser, and detector suites passed. Its processor
failures identified F01: the older persistence-test ADMF fixture lacked mandatory
NE status. The fixture was corrected without weakening response validation or
any authorization assertions. The complete corrected processor suite then passed
with `go test -json -tags all,li ./internal/pkg/processor` (33.174 seconds).

Final focused delivery/replay race verification passed:

```sh
go test -race -tags all,li ./internal/pkg/processor ./internal/pkg/voip ./internal/pkg/li/x2x3 -run 'Test(ProcessorTapReplaysTCPReusePCAPToMDF|ProcessorSIPEmissionCoverageAndContentAdmission|SIPMetadataForLI|TCPDirectionRealReassemblyCarriesSenderToX2|X2Encoder_IRIOnlyBodyPolicy)' -count=1
```

`TestProcessorTapReplaysTCPReusePCAPToMDF` creates on-disk synthetic normal-close
and trailing-RST pcaps in both tuple orientations, replays them through the real
assembler and production tap handler, and checks actual processor-to-TLS-MDF
products. Eight SIP messages across both connections retain payload, addresses,
Call-ID correlation, and sequence order. A second-call RTP product retains X3
bytes and direction; task revocation suppresses subsequent media. No synthetic
capture artifacts are retained in the repository.

Final processor and tap builds passed with both LI and non-LI tags. `go vet
-tags all,li` passed for the affected LI, reassembly, capture, VoIP, processor,
parser, and detector packages. Changed Go and Markdown files were formatted;
`git diff --check` passed.

## Closure decision

**CLOSED.** One independent integrated discovery and one bounded post-fix review
found no material defect beyond F01, whose fixture correction and complete
processor recheck passed. Every scoped plan requirement has source/production
trace and regression evidence; no required check is deferred. The notification
extension and SMS/HI2 limitations described above are outside this plan's
implementation contract, rather than claims of additional compliance.

Synthetic tests establish local production-path behavior; no production
deployment or capture timing claim is made. The verified plan and code are
committed as three independently reviewable workstreams.

SIP emission was committed as `cfa32517`; TCP reuse and integrated replay as
`a4a6b815`. The ADMF recovery commit includes this review and the completed plan.
