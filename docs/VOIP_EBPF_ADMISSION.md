# Selective VoIP media capture with eBPF

See the [implementation plan](plans/voip-ebpf-media-admission.md) and
[verification results](plans/voip-ebpf-implementation-results.md) for the tested
behavior and qualification limits. The [research report](research/voip-ebpf-media-admission.md)
records the design decisions.

`lc hunt voip --rtp-ebpf` and `lc tap voip --rtp-ebpf` enable Linux socket-level
admission of media candidates. The feature is off by default. Other commands keep
their existing capture behavior. libpcap still reads packets; a persistent eBPF
socket filter consults maps updated when selected calls gain or lose media
endpoints. Call activity does not restart capture, replace its socket/program, or
call `SetBPFFilter`.

```bash
sudo lc hunt voip -i eth0 --processor processor:55555 \
  --tls-ca ca.crt --rtp-ebpf

sudo lc tap voip -i eth0 --sip-user alice --rtp-ebpf \
  --tls-cert server.crt --tls-key server.key
```

## Capture and selection

The kernel admits candidates. Existing userspace checks remain authoritative for
call ownership, filter provenance, authorization, expiry, and output. A matching
endpoint does not assign a Call-ID or authorize delivery. Independent IP/CIDR
selectors and the configured no-filter policy continue to work; an empty IP
selector map alone does not mean there are no filters.

**Hunter upgrade behavior:** `--no-filter-policy` defaults to `deny`, so an empty
applicable filter set forwards no calls. VoIP hunters now apply distributed
application filters even when eBPF is disabled; upgrading from the earlier
receiver-interface mismatch can reduce forwarded traffic. Deliberate broad
selection requires an empty applicable filter set and `--no-filter-policy allow`.
Installed filters and explicit capture predicates continue to apply.

With `--rtp-ebpf`, including shadow mode, hunt and tap IP/CIDR selectors can select
eligible media independently of a selected call, subject to explicit packet
predicates and userspace output checks. With eBPF disabled, tap routes IP/CIDR
filters through classic BPF. A mixed IP and SIP-identity configuration can capture
IP-matched RTP but reject it in userspace without a selected-call association;
disabling admission does not preserve that output for unassociated media. True
IP-only tap configurations have no SIP-identity filter requiring the association.
Hunter IP/CIDR media selection remains independent with eBPF enabled or disabled.

For call-selected media, selective capture starts after selection and endpoint
publication.
There is no pre-match RTP history. Bounded SDP metadata from validated, unmatched
SIP messages can be promoted when the same dialog later matches. Promotion does
not recover packets already rejected by the kernel. Media arriving between SIP
selection and map publication can also be lost. Offer/answer and provisional SDP
can supply endpoints before a call is answered.

The shared parser recognizes IPv4/IPv6 connection addresses, media-level
overrides, multiple RTP streams, default and explicit RTCP endpoints, and RTCP
mux. Disabled or inactive descriptions contribute no new endpoints. The existing
call policy retains accepted endpoints until authoritative cleanup, including
trailing-media grace; a new description does not silently remove an opposite-side
or previously valid endpoint. Metadata is bounded by dialog count, endpoint count,
bytes, and expiry. Expired or evicted metadata can make later promotion unavailable.

RTP port 65535 cannot derive the default next-port RTCP endpoint: 65536 is outside
the valid UDP port range. The parser conservatively rejects that whole media
section when RTCP is implicit. Port 65535 is supported with `a=rtcp-mux` or
`a=rtcp-mux-only`, or with a valid explicit `a=rtcp:` port/address. Invalid RTCP
still invalidates the section; independent valid media sections remain usable.

By default all captured interfaces share observation domain zero: SIP on one
interface can admit media on another. Explicit domains separate overlapping local
observations, including registry ownership, inherited selection, TCP streams and
IP fragment reassembly. Domain configuration must agree with where signaling and
media are visible. Assigning them to different domains prevents correlation.
Configured call, endpoint-association and positive TCP-stream budgets are
partitioned across domain processors rather than multiplied. A positive budget too
small to assign a nonzero share is rejected at startup; zero TCP streams retains
its existing unlimited meaning.
Domain isolation is local capture attribution; central output grouping still uses
the original SIP Call-ID. Identical visible Call-IDs are not rewritten.

## Explicit restrictions and compatibility

The user-provided `--filter` predicate runs before every admission bypass. Explicit
`--udp-only`, `--sip-port`, and `--rtp-port-range` settings are also retained.
Automatically generated RTP ranges are not applied to learned endpoints. Thus a
selected SDP endpoint outside 10000–32768 can be captured unless an explicit
restriction excludes it. `--udp-only` excludes TCP signaling and ESP.

With no SIP-port constraint, TCP reassembly input and non-media UDP remain
available for arbitrary-port SIP discovery. A conservative RTP/RTCP header test
identifies packets eligible for dynamic media rejection. This is a capture-load
optimization; it does not promise rejection of every possible unrelated UDP
packet.

Fragments, bounded-parser unknown forms, deep IPv6 extension chains, VXLAN and
enabled ESP-NULL use counted packet-local compatibility admission where complete
endpoint inspection is unavailable. Non-initial fragments cannot supply ports.
Compatibility preserves the explicit base predicate and known protocol
restrictions, but can reduce selectivity. An unfamiliar packet never opens the
entire domain. VXLAN traffic containing ESP follows the same compatibility rule.

The current supported link type is Ethernet, including ordinary single/double
VLAN headers. Endpoint lookup works with hardware-stripped VLAN headers. Explicit
`vlan` capture expressions are rejected until offload-aware predicate composition
is supported. Linux cooked capture, including the usual `any` device, is rejected
when admission is enabled. Unsupported predicate instructions fail at startup;
they are not replaced with a broader predicate.

## Configuration

Only the two VoIP subcommands expose these flags:

| Flag                        | Default   | Meaning                                              |
| --------------------------- | --------- | ---------------------------------------------------- |
| `--rtp-ebpf`                | `false`   | Explicitly enable admission.                         |
| `--rtp-ebpf-mode`           | `enforce` | `enforce` or diagnostic `shadow`.                    |
| `--rtp-ebpf-failure-policy` | `open`    | Runtime update failure behavior: `open` or `closed`. |

Setting a mode or failure policy does not enable the feature. CLI values override
YAML, including an explicit `--rtp-ebpf=false`. Advanced settings live below
`hunter.voip.rtp_ebpf` or `tap.voip.rtp_ebpf`:

```yaml
tap:
  voip:
    rtp_ebpf:
      enabled: true
      mode: enforce
      failure_policy: open
      interface_domains:
        eth0: 1
        eth1: 1
        eth2: 2
      endpoint_capacity: 40000
      owner_capacity: 10000
      max_endpoints_per_owner: 32
      pending_dialog_capacity: 10000
      pending_endpoint_capacity: 40000
      pending_bytes: 8388608
      pending_ttl: 30s
      replay_window: 2m
      replay_guard_capacity: 10000
      replay_guard_bytes: 2097152
      expiration_batch: 256
      retry_interval: 1s
      shadow_evidence_capacity: 1024
      missing_media_interval: 30s
```

Unassigned interfaces use domain zero. Domain IDs must be below 4096. Capacities
and durations must be positive. Endpoint capacity counts distinct map entries;
shared endpoints remain installed until their final eligible owner is removed.
Per-owner limits count RTP and separate RTCP endpoints. Pending metadata has
independent limits so unmatched call churn cannot grow memory without bound.
The controller separately bounds pending owner tokens by `pending_dialog_capacity`
across all domains. These tokens retain a selected lifetime while active owner
slots are full; endpoints remain in the authoritative call registry and are retried
without requiring another SDP message. They do not count as active owners or
retain packet payloads. Metadata and token pools each enforce their stated bounds.
These defaults are resource settings, not throughput or latency guarantees.

The authoritative tracker budget also includes retained legacy port-only
diagnostic keys. Those keys cannot authorize media, but can consume space needed
for later exact endpoints during media moves. This shared accounting and separate
RTCP endpoints predate the follow-up remediation. Without admission, the ordinary
tracker has a library default of 64 endpoints per call and the local VoIP
processor has a default of 32. Their current command wiring exposes no operator
endpoint-limit setting. Admission resource settings are separate from those
ordinary registry defaults; increasing admission capacity does not raise an
ordinary-path endpoint limit. Account for diagnostic keys and separate RTCP when
interpreting resource-limited warnings. Malformed RTCP invalidates its whole media
section, including otherwise usable RTP. Finer salvage and separate diagnostic
storage remain future enhancements.

Selected derivation descriptors are bounded separately using the pending dialog,
byte and endpoint settings across all observation domains in the capture session,
with at most one retained predecessor per context and an owner context count
bounded by the per-owner endpoint setting. Exhaustion
preserves unknown state until the affected lifetime retires; reducing history
must not manufacture complete negotiation evidence.

## Reliable provisional answers

Admission recovery supports the delayed-offer sequence of an observed bodyless
INVITE, an initial tagged reliable provisional response (for example, 183)
carrying the SDP offer with valid `Require: 100rel` and `RSeq` headers, and a
complete SDP answer in matching PRACK. Proof requires the same dialog fork and
selected call lifetime: PRACK's RAck response number must match RSeq, and its
referenced CSeq number/method must match the provisional response's INVITE
CSeq. PRACK's own CSeq and Via branch identify its separate transaction. The
offer alone, a bodyless final response or ACK, and unrelated PRACK SDP cannot
resolve the missing answer. Missing, conflicting, expired unmatched or
capacity-lost proof remains uncertain; independently safe endpoints can still
be promoted. Other unresolved contexts, failed endpoint promotions or control
writes also prevent recovery. Retained linkage is bounded and absent from
status and warning logs.

Recovery retains bounded reliable offer/answer linkage per request initiator and
dialog fork. The initial reliable response must have RSeq between 1 and 2^31-1;
later valid reliable responses remain subject to exact linkage and acknowledgment.
Unmatched linkage expires with `pending_ttl`. Once the answer is validated, its
bounded current-lifetime context survives that expiry until applicable
supersession or retirement. An exactly matched rejection of the PRACK restores
uncertainty.

The reliable provisional offer requires its answer in PRACK, as defined in
[RFC 3262 section 5](https://www.rfc-editor.org/rfc/rfc3262.html#section-5).
SDP in ACK after a bodyless PRACK does not substitute for that missing admission
proof; this exchange remains uncertain. Ordinary processor SDP association is a
separate behavior and may still associate endpoints from ACK. An early UPDATE
cannot answer an outstanding
reliable provisional offer. Early and established-dialog UPDATE have different
offer/answer constraints, as described in
[RFC 3311 section 5.1](https://www.rfc-editor.org/rfc/rfc3311.html#section-5.1).

After an observed successful final INVITE response establishes the dialog, a
complete confirmed re-INVITE or established-dialog UPDATE from either participant
can supersede applicable negotiation uncertainty in that same dialog and live
call. This includes conflicting transaction headers, faulty PRACK, unresolved
delayed offers and partial SDP. Freshness is checked in the repair initiator's
sequence space; caller and callee CSeq numbers are never compared with each other.
A request alone, partial or rejected answer, conflicting replacement headers,
stale exchange or another dialog cannot establish recovery. Independent unresolved
contexts, lost lifecycle/resource evidence, failed endpoint promotions and control
writes still prevent restored enforcement.

In enforce mode, obsolete uncertainty-only endpoint ownership remains available
for the role's trailing-media grace. Endpoints required by a healthy historical
exchange, the complete repair, or an independent obligation remain protected;
partial or conflicting observations do not become healthy history merely because
they were retained. Valid negotiation that takes an endpoint back cancels only
that endpoint's pending retirement. Cleanup rechecks exact lifetime and current
independent requirements; a stale callback cannot remove a reused lifetime's
ownership. Authoritative call completion leaves final cleanup to completion
grace. Healthy re-offers and hold/resume retain historical registry ownership.
Shadow recovery advances proof and diagnostics while preserving userspace endpoint
ownership. Retirement state uses existing configured metadata and per-owner limits.

Tap uses its effective `--pcap-grace-period` for both endpoint retirement and
call completion, with nonpositive values normalized to the existing five-second
default before routing is constructed. Hunter uses its configured `PCAPGracePeriod`
with the same five-second fallback; it has no `--pcap-grace-period` flag. A direct
low-level admission bridge can intentionally use zero for immediate retirement;
that library behavior does not change role startup defaults.

Grace protects attribution during its window, including an obsolete pair with
one endpoint shared by another call. After expiry, the existing one-sided
resolver fallback still applies: arbitrary late packets may resolve through the
remaining owner of a shared endpoint. Release markers that suppress that fallback
are secondary hardening and are not implemented by this change.

The SIP parser combines repeated `Require` lines and preserves the last singleton
`CSeq`, `RSeq` and `RAck` value for general consumers. Admission accepts identical
valid duplicates after semantic comparison: numeric fields ignore leading zeroes,
whitespace is normalized and SIP methods compare case sensitively. A malformed
singleton RSeq or RAck invalidates its reliable linkage without making an otherwise
valid ordinary offer/answer uncertain. A repeated group containing any malformed
value remains conflicting, including valid/malformed mixtures and identical invalid
repetitions. Conflicting CSeq retains only bounded valid minimum/maximum evidence
for its initiator; method conflicts and malformed or unavailable bounds remain
explicitly uncertain. A complete clean confirmed replacement must exceed the
applicable uncertainty watermark. Safe selected-call SDP endpoints may still be
learned within configured limits, without authorizing output or supplying proof.
The open/closed failure policy and all explicit capture/userspace restrictions
remain in force.

The parser retains the validated `CSeqMin`/`CSeqMax` range so the evidence
accurately describes every valid occurrence, independently of the last header
value exposed to general consumers. Recovery currently uses only `CSeqMax` as
the freshness bound; `CSeqMin` is retained for the parser evidence contract and
its range validation, not as a second recovery threshold.

Pending proof, endpoint provenance and delayed cleanup are bound to authoritative
call lifetimes. Explicitly bound old session/generation evidence is rejected even
after replay history expires. Retirement records bounded exact prior-initiator
sequence guards to quarantine reused wire identities during `replay_window`
(default `2m`), measured from retirement using the bridge's monotonic clock rather
than packet timestamps. A subsequent retirement of the same identity refreshes
its window; replay observations do not extend it. Malformed conflicts without
usable bounds block that initiator; lost identity/bounds block the reused Call-ID
within the window.

Replay history has a separate exact-only pool shared across observation domains:
`replay_guard_capacity` (default `10000`) and `replay_guard_bytes` (default
`2097152`), with 128 accounted bytes per entry. Both bounds apply; history does
not consume live selected-derivation capacity. Unexpired guards are never evicted
for new entries. Expiry maintenance in the existing worker scans the exact map,
with work bounded by the configured capacity. Close releases the accounting.
There is no probabilistic overflow store.

If a retirement guard cannot be recorded, all proof in that observation domain
is conservative until the last unrecordable retirement plus `replay_window`.
This fallback preserves existing exact guards and follows the configured open/closed
policy. Sustained overload may extend the interval. Healthy retained proof is not
marked missing by INFO, OPTIONS or exact retransmissions that add no media proof.
New proof-bearing observations enter a quarantine bound to the authoritative active
lifetime and charged to the existing selected-derivation context, byte and endpoint
limits. Quarantined evidence cannot authorize media or install endpoint ownership.

At the pressure deadline, recovery requires a complete accepted exact exchange entirely
observed after pressure began, covering every quarantined obligation and revalidated
against the current lifetime and surviving exact replay guards. A cached pre-pressure
answer cannot substitute for missing evidence. Elapsed time alone never makes a call
known. Explicit old lifetimes remain rejected, and both configured open and closed
policies preserve proof uncertainty.

Quarantine expires at its first observation plus `replay_window` plus `pending_ttl`;
retransmissions and repeated pressure never extend that fixed deadline. Incomplete,
exhausted or expired quarantine releases its reservations while the affected call
remains unknown until a fresh complete post-pressure exchange or configured call-lifetime
expiry. Unrelated calls are not held indefinitely. Retiring a call with missing evidence
records a blocked Call-ID guard for the window. Aggregate warnings are rate limited to
the retry interval and include no wire identities.

Retry maintenance performs global replay-guard and quarantine expiry scans, bounded
by configured capacities. SIP processing checks logical deadlines only for the touched
lifetime, exact guard and call recovery; expired evidence cannot authorize media between
maintenance ticks.

The two-minute default is an engineering margin over the usual 32-second
64-times-T1 SIP transaction horizon with T1 at 500 ms, described in
[RFC 3261 section 17.1.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.2),
and the existing 30-second `pending_ttl`. It is not a bound on all SIP dialogs,
TCP reassembly, capture queues, hunter buffering, or forwarding delays. Configure
the window for known deployment delays. After it expires, unbound identical wire
identities cannot distinguish a fresh exchange from an old capture or delayed
message; arbitrary replay remains outside this finite protection guarantee.

Early-dialog proof is kept separately for each bounded fork. Observed confirmation
resolves the winning dialog; losing-dialog exclusive ownership follows trailing
media grace while shared and independent requirements remain. Multiple successful
forks remain conservative. Both an INVITE offer with its reliable-response answer
and a delayed offer with its PRACK answer can retain the canonical accepted SDP
while identical SDP repeats in a later reliable provisional. Each new provisional
requires its own valid next RSeq and matching RAck/PRACK in the same lifetime and
early dialog. Same-RSeq retransmissions do not create a new acknowledgement debt.
Changed SDP remains conservative and add-only until valid repair; final 200
repeating the canonical answer cannot bypass an outstanding PRACK. Equal SDP
bytes alone cannot validate unrelated RSeq, RAck, dialog or lifetime evidence.

Per-domain `rtp_ebpf.scopes[].uncertainty` reports unique active `unknown_calls`
and overlapping reason counts: `conflicting_headers`, `faulty_prack`,
`partial_sdp`, `delayed_offer`, `fork_ambiguity` and `evidence_loss`. One call can
have several reasons; do not add the reason counts to obtain a call total.
`identical_duplicates` and `conflicting_duplicates` are cumulative counts of
messages bearing a repeated singleton header group, counted separately for
CSeq, RSeq and RAck. Three or more repeated lines in one group count once, not
once per line; these counters do not count currently unknown calls. Identical
valid duplicates alone create no uncertainty.

`malformed_rseq` and `malformed_rack` separately count parsed messages containing
at least one malformed occurrence of that header kind, once per kind per message,
including retransmissions. A mixed or invalid duplicate group increments both its
malformed-kind counter and `conflicting_duplicates`; a malformed singleton does
not increment the duplicate counter. These occurrence counters are independent
of active unknown-call totals and may overlap.

`replay_guards` and `replay_guard_bytes` report per-domain exact-history usage;
`replay_guard_capacity` and `replay_guard_byte_limit` are shared pool bounds,
not allowances multiplied by domain count. `replay_window_ns` reports the effective
configured window. `replay_unrecorded` cumulatively counts failed guard insertion
attempts, and `replay_degraded_ns` is the remaining domain-wide conservative
interval, zero when inactive. Active calls affected by that interval also appear
in unique unknown-call totals and overlapping `evidence_loss` counts. These
fields require no identities or dynamic labels; older peers omit them.

`degraded_since_unix_ns` identifies the current degradation start and
`degraded_duration_ns` its elapsed duration, including degraded-closed and
control-failed states. Successful complete reconciliation resets both;
`open_duration_ns` remains cumulative confirmed-open time and has a different
meaning. CLI status JSON exposes these additive fields. The Nodes view displays
aggregate admission diagnostics for the selected hunter or processor/tap in
both table and graph layouts. No endpoint addresses, call identities or raw
parser/backend errors appear in these diagnostics. Older nodes omit the new
fields and older clients ignore them.

## Failure and diagnostic modes

Explicit enablement fails startup if required maps, program attachment, privileges,
link type or configuration cannot be supported. There is no automatic fallback to
broad capture or shadow mode. Capture readiness is reported only after every
requested interface has installed policy. Partial initialization is unwound.

| State           | Meaning                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------- |
| Disabled        | Existing capture; no eBPF admission resources.                                              |
| Initializing    | Required policy is not yet ready.                                                           |
| Enforcing       | Selected endpoint and independent-selector admission is active.                             |
| Shadow          | Explicit restrictions apply; dynamic rejection is observed but bypassed.                    |
| Degraded-open   | Affected domain bypasses dynamic media rejection after confirmed synchronization failure.   |
| Degraded-closed | Keep valid installed admissions while reporting missing or unsynchronized state.            |
| Recovery        | Reconcile the entire current endpoint and selector set before restoring normal mode.        |
| Control-failed  | A requested mode write failed; last confirmed mode and uncertainty are reported separately. |

Open is the default runtime failure policy. A separately preallocated control map
allows opening even when the endpoint map is full. If the control write itself
fails, status does not claim fail-open succeeded. Explicit restrictions and all
userspace authorization checks remain in force. Recovery includes additions,
deletions, selector changes and current ownership; one successful map update is
not sufficient evidence of recovery. Unresolved SDP is tracked by media sender,
request initiator and current lifetime. A complete opposite-side answer adds its
own knowledge without repairing an incomplete offer. Recovery requires a proved
same-context repair, supersession or transaction retirement, followed by confirmed
complete reconciliation. SDP in unrelated SIP methods cannot supply that proof.
Rejecting a later offer restores any unresolved predecessor; an observed successful
negotiation can retire it. Failed endpoint associations remain pending across all
still-current contexts; an unrelated message or opposite-side answer cannot erase
them. Only successful association or proved context supersession/retirement can
remove that requirement. Persistent failures can keep a domain degraded.
If even the bounded pending-owner pool is exhausted, the lost selection is marked
unknown and ordinary retries cannot establish completeness. Restart the enabled
capture after correcting capacity/traffic conditions, or let every authoritative
call retire so the registry is empty. An unselected call can also prevent this
empty-registry recovery. The application must not silently declare recovery from
an incomplete owner set.

Status includes configured/effective modes, desired/installed generations,
occupancy, pending changes, update/control errors, compatibility decisions,
metadata eviction/expiry, and diagnostic evidence loss. Existing capture-drop
counters retain their meaning. Ordinary status does not expose endpoint addresses,
selector values, packet payloads or Call-IDs.

`--rtp-ebpf-shadow-sample-every=N` uses a deterministic rule shared by the kernel,
capture observation and verified attribution. For complete frames up to 256 bytes,
the rule hashes the domain, frame length and all frame bytes. `N=1` includes every
eligible identity; larger values select approximately one in N. Identical copies
share eligibility, and all eligible copies count toward duplicate detection.
Hashes choose samples; exact bytes establish identity. Unsampled observations do
not acquire correlation locks or allocate entries. Oversized or unavailable full
frames can produce incomplete diagnostic samples but cannot be correlated.

**Shadow sizing warning:** the defaults retain only 1024 distinct eligible frame
identities, sample every identity (`N=1`) and keep entries for about 60–61 seconds.
This leaves little room for distinct eligible background traffic. Dividing 1024
by that retention window gives roughly 17 distinct eligible identities per second
before reserving burst headroom. This is a theoretical storage-sizing calculation,
not a supported packet rate, measured throughput or acceptance threshold. An
identity is a complete frame, so changing sequence numbers or payloads create new
identities even within one flow.

The correlator holds distinct eligible full-frame identities, bounded by
`shadow_evidence_capacity`. Entries expire strictly after twice `pending_ttl`,
then at the next `retry_interval` maintenance pass. Approximate capacity sizing
uses eligible distinct identities per second multiplied by that retention window,
plus burst headroom. With the default TTL and maintenance interval, the window is
about 60–61 seconds. `pending_ttl` also controls pending SIP metadata; shortening
it changes promotion behavior. Retired owner history lasts beyond three TTLs and
remains bounded by the owner capacity. The separate diagnostic sample history is
bounded by the same evidence-capacity setting but counts sample occurrences and
can overwrite independently of the identity table.

As eligible identity volume grows, consider increasing the sampling interval
before increasing capacity. Sampling reduces both retained identities and hook
work while counting every copy of each eligible identity. Larger capacity
retains more evidence but increases memory and maintenance work: maintenance
scans entries while holding the correlation mutex, and concurrent eligible
observations use `TryLock`. A lock miss is actual evidence loss and can prevent
classification; higher capacity alone does not guarantee complete evidence.

Storage grows separately for the full-frame correlation table, diagnostic sample
history, owner history and kernel ring. The identity table holds exact frame
bytes and correlation state; sample history holds bounded occurrences and can
overwrite independently; owner history is bounded by owner capacity; kernel-ring
storage is separately bounded. Sampling changes which observations enter these
paths but does not raise their configured capacities. No fixed per-entry memory
estimate or scan-duration guarantee is implied.

Distinguish expected rejection before selection, the selection-to-publication
interval and rejection after confirmed publication. Classification requires a
unique complete frame, capture observation, verified lifetime attribution and
historical generation/publication evidence. Duplicate, late, truncated or lost
evidence and configuration mismatches remain incomplete. Eligible overflow or
lock pressure invalidates unsupported uniqueness claims, including other pending
evidence; continued loss can prevent useful classifications. Sampled observations
are not exact whole-traffic rejection counts or live-capacity/parity guarantees.
No frame contents or signaling identities are exposed in status or warning logs.

SDP endpoint derivation warnings are aggregated on maintenance, at most once per
30-second reporting interval, with one final outstanding summary on shutdown.
They use the normal logger level and report only sanitized reasons and counts of
partial, failed, resource-limited and suppressed observations. Sniff and hunter
use the buffer's reporting path to avoid duplicate tracker warnings; standalone
tap uses its local processor and distributed processing has its own complete-SIP
reporting path. This reporting does not require eBPF or structured-log output and
does not wait for log I/O on the packet path.

Selected, answered calls without attributed media produce a diagnostic after the
configured interval. Installed endpoints and kernel-admitted candidates are
separate from final userspace-attributed media. Hold/inactive media, routing,
observation placement and NAT may explain missing media. This diagnostic does not
automatically widen capture.

## Build, startup, and verification

The loader requires Linux BPF socket programs and ring buffers (Linux 5.8 or later
feature set), plus permission to create maps/load programs and capture packets.
The privileged tests run in an isolated container. Capability restrictions,
security policy and kernel configuration can still prevent loading; initialization
returns the actual failure.

The pinned local gopacket extension owns attachment inside the libpcap binding.
It never extracts a private C pointer or closes a borrowed socket descriptor.
Ordinary builds consume embedded BPF objects and do not require clang. Generation
uses the recorded container toolchain:

```bash
internal/pkg/capture/ebpfadmission/toolchain.sh generate
make test-ebpf
```

`make test-ebpf` requires Docker and explicitly runs a disposable privileged
container with its own network namespace. It verifies real kernel decisions,
libpcap attachment, and command behavior. Default unprivileged tests report these
cases as not exercised. The prior remediation's isolated kernel and command run
is recorded in [its execution record](plans/voip-admission-inventory-review-remediation.md#execution-record);
a verifier that did not repeat that run should reference it as implementation
evidence. Compiler/container caches are ephemeral; generated source
and both endian objects are checked in. See the
[backend notes](../internal/pkg/capture/ebpfadmission/README.md) and
[binding patch provenance](../third_party/gopacket/LIPPYCAT_PATCH.md).

Enabled handles use immediate mode, attach a startup reject-all policy, drain
retire earlier kernel receivers and queued socket/ring data, then activate the
final program. This deliberately permits counted startup packet loss. Future
packets are not compared to a permanent wall-clock boundary, so clock rollback
does not create a discard window. Unsupported ring-drain modes fail startup.

libpcap remains a cgo dependency. Cgo is not single-threaded and does not disable
Go goroutines. This feature avoids unnecessary packet delivery and decoding; it
does not replace capture with native AF_PACKET or remove cgo across the project.
Performance measurements compare equivalent broad/shadow/enforce traffic and
record environment and compatibility passes. The 100 calls/s scenario is workload
context, not a new acceptance threshold.
