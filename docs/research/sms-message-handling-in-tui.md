# SMS (SIP MESSAGE) Handling in the VoIP TUI

Status: implemented (call-state fix) + design analysis (SMS-text display, not yet built)
Date: 2026-07-01
Context: SMS-over-IMS interception on `de.lyca` (tap mode), observed via `lc watch remote`.

## Problem

SMS-over-IMS is carried as SIP `MESSAGE` requests (pager mode), not as a dialog.
A `MESSAGE` transaction is just `MESSAGE` → `200 OK` (or `202 Accepted`); there is
**no `INVITE` and no `BYE`**.

The TUI call model was built for dialogs. When an SMS was captured:

1. The `MESSAGE` request created a call entry that stayed in state `NEW`.
2. Its `200 OK` (CSeq method `MESSAGE`) fell through to the "2xx answers the
   call" branch and promoted the entry to `ACTIVE` — exactly like an answered
   `INVITE`.
3. With no `BYE` ever arriving, the entry sat `ACTIVE` forever and the TUI counted
   its duration up indefinitely (observed: `27m41s` and climbing for a
   multi-second SMS).

## Fix (implemented)

Introduce a dedicated terminal call state, displayed as **`SMS`**, and classify a
standalone `MESSAGE` as that state with `EndTime` stamped at the transaction time
so the duration freezes instead of climbing.

The call-state machine exists in **three synchronized places** (the enums are
bridged by string, not by ordinal — `call_aggregator.go` already carries an extra
`CallStateEnding` the TUI enum lacks — so new states must be *appended*, never
inserted):

| File | Change |
|------|--------|
| `internal/pkg/remotecapture/client_conversion.go` | `deriveSIPState`: added `case "MESSAGE"` → `State = "SMS"`, set `EndTime`. Added `"SMS"` to the terminal-state guard and to `isTerminalCallState` (so the trailing `2xx` can't reactivate it, and the terminal transition is flushed to the TUI immediately). Also handles the response-first case (`cseqMethod == "MESSAGE"` in the 2xx branch). This is the path that drives `lc watch remote`. |
| `internal/pkg/voip/call_aggregator.go` | Appended `CallStateMessage` to the enum, `String()` → `"SMS"`, and mirrored the `MESSAGE` method + `cseqMethod` handling in `updateCallState` (keeps local `lc watch live` consistent). |
| `internal/pkg/tui/components/callsview.go` | Appended `CallStateMessage` to the enum, `String()` → `"SMS"`, and a color case (violet, like a completed/ended transaction). Duration column already uses `c.Duration` for non-`Active`/`RTPOnly` states, so `SMS` does not climb. |
| `internal/pkg/tui/model.go` | `mapCallState`: `"SMS"`/`"MESSAGE"` → `components.CallStateMessage` (string→enum bridge for the remote path). |

Tests added in `internal/pkg/remotecapture/client_test.go`:
`TestUpdateCallState_MessageIsSMSTransaction` (request-first, request then 200 does
not reactivate) and `TestUpdateCallState_MessageResponseFirst` (lone 2xx still
classifies as SMS). Existing state tests still pass; `go build -tags all,li` clean.

### Duration behaviour

`CallInfo.Duration` is computed on flush: `EndTime - StartTime` when `EndTime` is
set (`client_conversion.go`), which for an SMS is the ~ms transaction time. The
TUI duration column returns `time.Since(StartTime)` only for `Active`/`RTP-only`
states and `c.Duration` otherwise — so an `SMS` entry shows a frozen, tiny
duration.

## Feature analysis: showing the SMS text in the details pane (NOT yet built)

The details renderer (`callsview.go:renderCallDetailsContent`, ~line 1197) is a
plain `strings.Builder`; adding a `💬 Message` section is trivial **once the text
is available on the `Call` struct**. The real work is sourcing and decoding the
text.

### Constraints

1. **The body is not currently carried to the TUI.** `data.SIPMetadata`
   (`api/gen/data/data.pb.go`) has no body field — only method, Call-ID, URIs,
   tags, response code, P-Access-Network-Info, CSeq. `CapturedPacket.Data`
   carries the raw packet bytes, but nothing extracts/forwards the SIP body.
2. **The body is binary, not readable text.** SMS-over-IMS uses
   `Content-Type: application/vnd.3gpp.sms` — an RP-DATA wrapper around a
   GSM 03.40 `SMS-DELIVER`/`SMS-SUBMIT` TPDU whose user data is 7-bit-packed
   (GSM 03.38 default alphabet) or UCS2. This is exactly what had to be decoded
   to read "Test 123" earlier (via the PHP `asn1decode` `decode3gppSms`). There is
   **no Go 3GPP-SMS/TPDU decoder in lippycat today** (`internal/pkg/li/x2x3/pdu.go`
   only carries the content-type/body as opaque TLV attributes for X2/X3).

So the feature = a Go 3GPP-SMS decoder + plumbing the decoded text to the TUI
`Call` + rendering it.

### Architecture fork (needs a decision before building)

**Where to decode + plumb:**

- **(A) Capture-side + proto field (recommended).** Decode on the hunter/capture
  side where the SIP body is already parsed; add an `sms_text` (and maybe
  `sms_content_type`) field to the `SIPMetadata` proto, regenerate `data.pb.go`,
  and render it. Uniform for both local (`lc watch live`) and remote
  (`lc watch remote`). Cost: proto change + regen + capture-side SIP-body
  handling.
- **(B) Client-side from raw bytes.** Parse the SIP body out of
  `CapturedPacket.Data` in `remotecapture` and decode there. No proto change, but
  benefits only the remote path and duplicates SIP-body parsing client-side; also
  depends on `Data` carrying the full inner packet after ESP-NULL decap.
- **(C) Raw body only (quick).** No decoder: show `Content-Type` + body as
  hex/ASCII. Fast, but not human-readable for 3GPP-encoded SMS.

**Decoder scope (if building one):**

- **Single-part GSM7 + UCS2** — covers most real SMS; concatenated messages show
  per-segment.
- **Full** — add UDH-based multipart reassembly, 8-bit data, national-language
  shift tables. Most correct, larger code + test surface.

### Recommendation

Approach **(A)** with a **single-part GSM7 + UCS2** decoder first (extend to
multipart later if needed). It keeps decode logic on the capture side (one place,
reused by every consumer), makes the text available to both TUI modes and any
future LI export, and matches where SIP is already parsed. The proto change is the
main cost but is a one-time, additive field.

## Related

- `docs/research/hunt-tap-voip-filtering-issues.md` — SIP-over-TCP / ESP-NULL
  capture path.
- Capture-gap note: in the `test_call_2026-07-01-10.pcap` multi-SMS test, the
  *middle* SMS produced zero target-endpoint ESP frames in either the tcpdump or
  lippycat's live capture (the port-5060 OPTIONS keepalives kept flowing, proving
  the capture was alive) — i.e. that specific drop was upstream of lippycat
  (mirror/IMS path), not a reassembly bug. Unrelated to the TUI display issue
  fixed here.
