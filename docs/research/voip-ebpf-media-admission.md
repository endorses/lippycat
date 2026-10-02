# Selective VoIP Media Capture with eBPF

**Date:** 2026-10-02

**Status:** Research and design discussion; not implemented

**Scope:** Explicitly enabled live capture for `lc hunt voip` and `lc tap voip`

## Problem and objective

The current capture path can receive all RTP traffic admitted by its broad capture
filter, including media that userspace subsequently discards because its call does
not match a configured filter. Receiving, decoding, queuing, and correlating those
packets consumes resources even when they are never forwarded or written.

The proposed feature moves media admission into an eBPF socket filter. SIP parsing,
SDP extraction, call selection, and authoritative media attribution remain in Go.
Once a call matches, userspace installs its advertised media endpoints in a kernel
map. Unrelated media is rejected before delivery to the capture receive ring.

The motivating workload may reach **100 calls per second**, with multiple legs per
call and only a subset of calls matching. This is workload context, not a measured
capacity result or a new performance acceptance gate.

## Agreed requirements and recommended choices

The discussion established these requirements:

- Dynamic media admission must be explicitly enabled for hunter/tap VoIP. Existing
  capture behavior remains the default.
- Call-driven endpoint changes must not restart capture. They update eBPF map data
  while the socket and filter program remain active.
- Media becomes eligible only after its call matches. Retaining pre-match RTP is
  not required; the user explicitly chose capture after a match.
- Hunter and tap must use the same admission mechanism and preserve their existing
  application-level selection and attribution rules.

The following are recommendations, not finalized implementation decisions:

- Attach an eBPF socket filter to the existing Linux libpcap capture socket first.
  Introduce a direct AF_PACKET backend only if a concrete limitation warrants it.
- Retain bounded SIP/SDP metadata for late matches, without buffering pre-match RTP.
- Prefer an established Go capture implementation where it provides the required
  control. Avoid a custom ring implementation solely to eliminate cgo.
- Use a bounded ordinary hash map for admitted endpoints and explicit ownership
  tracking in Go.
- Share admission across capture interfaces in the same observation domain,
  with explicit separation for overlapping address spaces.
- Validate admission in an explicitly selected diagnostic shadow mode before
  enforcement, with timing-aware evidence and selected-call missing-media metrics.
- Reject startup with a clear error when explicitly requested eBPF capture cannot
  initialize, rather than silently reverting to broad capture.

No code changes, dependency selection, flag names, or benchmark results are implied
by this report.

## Current implementation and related research

The older [VoIP BPF optimization research](voip-bpf-filter-optimization.md)
identified the problem of losing RTP when capture is restricted to SIP ports. Its
solution used broad RTP port ranges. Historical commit `6e5d69b5` also discussed
general eBPF/XDP and hardware filtering in the former
`docs/research/high-speed-capture-strategies.md`, but did not specify this
SDP-driven admission-map design. Repository searches did not find a saved design
for that exact mechanism; this does not establish whether an unsaved chat existed.

Relevant current code:

| Component                                                                  | Current behavior                                                                                                        |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| [Hunter capture manager](../../internal/pkg/hunter/capture/manager.go)     | `Restart` recreates capture to apply changed capture filters.                                                           |
| [Tap local source](../../internal/pkg/processor/source/local.go)           | `SetBPFFilter` restarts capture for changed expressions; identical expressions are normally a no-op.                    |
| [Capture interface](../../internal/pkg/capture/pcaptypes/pcapinterface.go) | Exposes a concrete `*pcap.Handle`.                                                                                      |
| [Live capture setup](../../internal/pkg/capture/pcaptypes/live.go)         | Activates libpcap handles with capture buffer and timeout configuration.                                                |
| [Shared SIP orchestration](../../internal/pkg/sipflow/orchestrator.go)     | Selects SIP messages before registry observation. Unmatched SDP is not universally retained for later selection.        |
| [Hunter UDP handler](../../internal/pkg/voip/udp_handler_hunter.go)        | Registers SDP endpoints and resolves media through userspace call state. TCP handling also needs admission integration. |
| [Processor SIP integration](../../internal/pkg/voip/processor/sipflow.go)  | Registers advertised endpoints for selected SIP.                                                                        |
| [Call registry](../../internal/pkg/callregistry/call_registry.go)          | Maintains bounded, deduplicated, multi-owner endpoint associations and authoritative media resolution.                  |
| [Call tracker](../../internal/pkg/voip/calltracker.go)                     | Supports generation-safe completion with a trailing-media grace period.                                                 |

The restart constraint describes lippycat's current filter-update architecture;
it is not a claim that every use of libpcap's `pcap_setfilter()` must reopen a
socket. Regardless, the proposed per-call mechanism must bypass this restart path.

## Kernel and userspace responsibilities

```text
Incoming traffic
       |
       v
Existing libpcap-owned Linux packet socket with eBPF socket filter
       |
       +-- capture restrictions reject ----------------> discard from capture
       |
       +-- signaling / independent admission ----------> receive ring
       |
       +-- eligible UDP media endpoint in map ----------> receive ring
       |
       +-- other media --------------------------------> discard from capture

Receive ring -> existing Go packet pipeline
                         |
                         +-- SIP parsing and call selection
                         +-- SDP and dialog state
                         +-- endpoint admission controller -> kernel map
                         +-- authoritative RTP attribution and output filtering
```

This is a logical outline, not a complete packet parser or policy expression.
Fragments, encapsulation, signaling discovery, and independently selected packets
require explicit handling before it can become executable logic.

Use `BPF_PROG_TYPE_SOCKET_FILTER`, attached with `SO_ATTACH_BPF`. Rejection is scoped
to the capture socket; the objective is passive capture selection, not changing
host forwarding or dropping production traffic at an XDP hook. Socket filtering
still incurs receive-path work before its hook. Its expected benefit is avoiding
delivery and subsequent processing of unwanted capture packets.
[Linux socket documentation](https://man7.org/linux/man-pages/man7/socket.7.html)

The program remains attached across call starts and ends. Userspace adds, updates,
and deletes map elements through BPF operations. Per-call activity does not generate
new filter code. [Kernel map documentation](https://docs.kernel.org/bpf/maps.html)

## Endpoint keys, ownership, and multiple legs

A candidate endpoint key is:

```text
capture scope + address family + IP address + UDP port
```

Capture scope represents an observation domain, not necessarily the interface on
which SIP arrived. Signaling and media can arrive on different interfaces through
separate mirror sessions. Share a map across sockets observing the same domain;
do not automatically restrict an SDP-derived endpoint to the signaling interface.

For a process observing one address domain, the natural default is shared admission
across its capture interfaces. Deployments with overlapping address spaces need
explicit domain separation. An interface or VLAN may help identify a domain, but
must not automatically partition traffic that belongs together. Exact encoding,
configuration, and consistency with the userspace registry remain design work.
Both source and destination endpoints are checked.

Endpoint admission is preferable to requiring a complete five-tuple initially:
SDP may advertise one side before the other side is known, and the existing
correlation mechanism uses exact IP:port endpoints. A map hit admits a candidate
packet; it does not prove that the packet belongs to a particular selected call.

The controller maintains call/dialog/leg ownership in Go:

- A newly selected owner adds its distinct eligible endpoints.
- Repeated SDP for an existing association does not cause another insertion.
- A shared endpoint remains admitted while any eligible owner needs it.
- Ending one leg releases only that leg's ownership.
- Call-ID reuse and delayed cleanup use generations so an old callback cannot
  remove a new owner's admission.
- Matching one dialog must not automatically authorize another leg solely because
  it appears related. Cross-leg selection follows an explicit correlation policy.

Userspace remains responsible for ambiguity and filter provenance. The current
registry intersects endpoint owner sets when both are known, and an endpoint map
alone cannot reproduce that richer attribution decision.

Use a bounded hash map with explicit error handling. An LRU map can automatically
evict an active entry at capacity, making it unsuitable as an unnoticed source of
media loss. Kernel map values could carry lifetime/version information, but kernel
expiry, refresh scheduling, and stale-update rejection must be designed together;
a timestamp field alone does not implement expiry.
[Kernel hash-map documentation](https://docs.kernel.org/bpf/map_hash.html)

## Selection timing and buffering

| Approach                       | Unmatched-call state                                | Media received                                 |
| ------------------------------ | --------------------------------------------------- | ---------------------------------------------- |
| Strict matched-only            | Minimal signaling state                             | After selection and endpoint installation      |
| Retain SDP; matched-only media | Bounded SIP/SDP metadata                            | After selection, using already-known endpoints |
| Buffer pending-call media      | Signaling state, kernel entries, and packet buffers | Before selection as well                       |

The recommended approach is **bounded signaling retention with matched-only media**.
If an unmatched offer contains SDP and a later matching message does not, retained
metadata allows the controller to install the earlier advertised endpoints. The
current orchestrator does not universally retain that unmatched offer, so this
would be an explicit addition with bounds and expiry.

Retaining SDP does not require a kernel entry or RTP buffer for the unmatched call.
It does require correct dialog/transaction association so obsolete or unrelated SDP
cannot be promoted by a later match.

There is an unavoidable interval between receiving a relevant SDP packet and
publishing the resulting admission entries. Media arriving during that interval
may be missed, even if the SIP message matches. Pre-match buffering based on the
same userspace SDP parsing cannot recover packets rejected before installation.
The accepted absence of pre-match history is not evidence that any arbitrary
post-match publication delay is acceptable.

Map publication should happen promptly after authoritative selection and endpoint
registration, independently of output queues. The capture ring's block retirement
timeout also affects how quickly SIP reaches userspace, particularly when other
traffic is filtered out. Configuration and measurements should account for this.

Measure the entire arrival-to-publication path under load, including the receive
ring, dispatch queues, parsing/reassembly, selection, and map update. Prioritized
SIP processing does not remove delay incurred before classification. Enforcement
should reduce unrelated-media pressure, but selected traffic, independent
selectors, and compatibility admission can still create a backlog. Shadow mode
also retains the broad-capture load, so its timing is not automatically predictive
of enforcement timing.

## Call churn and map occupancy

For illustration, assume 100 calls/s, four distinct endpoint entries per admitted
call across all its legs, no sharing, and one insertion plus eventual deletion per
entry. At steady state:

| Admission policy                  | Approximate map operations per second |
| --------------------------------- | ------------------------------------: |
| Every call                        |                                   800 |
| Matched calls with 10% match rate |                                    80 |
| Matched calls with 1% match rate  |                                     8 |

These are arithmetic examples, not measurements. They exclude renegotiation,
refreshes, retries, RTCP-specific entries, and any replication between maps. Shared
endpoints and deduplication can reduce writes; additional streams and legs can
increase them.

For call rate `R`, selected fraction `f`, average selected lifetime `D`, and average
distinct endpoint count `E`, a rough occupancy estimate is `R * f * D * E`, before
sharing, grace periods, and other admission policies. A configured map capacity
must be enforced independently of this estimate.

Hundreds of map operations per second are not, by themselves, a reason to reject
pending-call buffering. The larger design concern is receiving and buffering the
media of calls that never match. A short pending window limits that cost but also
limits recoverable history. The user's chosen policy avoids that work.

## Libpcap versus direct AF_PACKET

Libpcap and AF_PACKET are not wholly separate Linux capture mechanisms. Libpcap
supports packet-mmap capture underneath, including TPACKET_V3. The choice here is
largely about socket ownership, attachment, and receive-ring control.
[Kernel packet-mmap documentation](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html)

| Approach                                      | Benefits                                              | Integration work                                                                                                             |
| --------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Libpcap with eBPF attached to its live socket | Retains existing packet handling and platform support | Extend the Go binding with a supported attachment operation; coordinate libpcap filter state and prevent replacement of eBPF |
| Direct AF_PACKET with eBPF                    | Explicit socket, filter, ring, and lifecycle control  | Add a backend adapter and validate packet metadata, ownership, shutdown, and statistics behavior                             |

Libpcap exposes the descriptor for an activated live capture through
[`pcap_fileno()`](https://www.tcpdump.org/manpages/pcap_fileno.3pcap.html). Our pinned
`github.com/google/gopacket v1.1.19` does not publicly expose the needed descriptor
or eBPF attachment operation. Its AF_PACKET package also lacks `SetEBPF`, although
later [upstream source](https://github.com/google/gopacket/blob/master/afpacket/afpacket.go)
contains that operation. A dependency change or supported adapter is needed;
private-field access is not a sound integration strategy.

The revised recommendation is **libpcap-backed eBPF admission first**, shared by
hunter and tap. This preserves existing timestamp, VLAN, decapsulation,
statistics, and shutdown handling while investigating selective admission. A
native AF_PACKET/TPACKET_V3 backend remains an alternative if a demonstrated
limitation of the libpcap integration warrants the additional work.

The initial integration needs a supported binding operation for attachment and
coordinated socket/filter ownership. Endpoint admission remains a separate
controller driven by authoritative call lifecycle observations. A general
backend-neutral reader is not a prerequisite; it becomes relevant if a second
capture implementation is actually introduced.

Preventing later `pcap_setfilter()` calls from replacing eBPF is necessary but
insufficient. Libpcap's Linux implementation can also apply a stored filter in
userspace, including temporarily filtering buffered blocks after a filter change.
The adapter must establish compatible userspace filter state, handle packets
already buffered before attachment, and reinstall the correct program/maps if a
socket is recreated. Simply obtaining the descriptor and attaching the program
does not settle these lifecycle details.
[Libpcap Linux implementation](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-linux.c)

Ring-backed packet slices must not escape into asynchronous consumers after their
ring storage is released. Initially, accepted packets can be copied into owned
storage before entering existing queues. TPACKET_V3 does not make the complete
pipeline zero-copy or bypass all kernel copying.

Startup must establish a documented admission boundary before normal processing.
With libpcap, the descriptor is obtained after activation, so the adapter must
explicitly handle packets received before eBPF attachment. If a direct backend is
introduced, attach filtering before enabling reception where possible.
Cancellation, poll wakeup, ring release, timestamp precision, VLAN offload metadata,
link types, and drop-counter semantics remain correctness requirements for either
integration.

## cgo and Go concurrency

**Cgo is not inherently single-threaded and does not disable goroutines.** A C call
occupies an OS thread, while the Go runtime allows other goroutines to run on other
threads. Multiple goroutines can call C concurrently when the library permits it.
The runtime explicitly transitions into C without blocking scheduling of other
goroutines. [Go runtime cgo implementation](https://go.dev/src/runtime/cgocall.go)

A goroutine waiting in libpcap therefore does not stop SIP processing, media
processing, or forwarding workers. Locks around one handle and constraints of an
individual library are separate from cgo's concurrency model.

Cgo has boundary-crossing, thread-occupancy, build, and memory-ownership costs.
Frequent calls in a packet loop may matter. Importing C for structure definitions
does not itself imply a C function call per packet.

Our pinned `gopacket/afpacket` imports C for Linux types and constants, retaining a
cgo build dependency. AF_PACKET itself does not require cgo: Go syscall bindings
and suitable ring structure definitions can implement the capture path. A pure-Go
path should be preferred when practical, but avoiding cgo alone does not justify
maintaining a custom mmap-ring implementation.

[`cilium/ebpf`](https://ebpf-go.dev/) can load programs and manage maps without cgo
or libbpf. The packet filter can be written in C and compiled ahead of time into an
embedded object using [`bpf2go`](https://ebpf-go.dev/guides/getting-started/). That
build step does not introduce cgo calls into packet capture.

Even if this new capture path avoids cgo, the complete binary can still depend on
it through libpcap or other existing functionality. Project-wide cgo removal is
not an objective of this feature. The primary expected gain is earlier rejection
of unwanted media; removing per-packet cgo crossings would be an additional gain
to measure, not a prerequisite for parallelism.

## Capture expressions and independent filters

Linux allows one attached socket filter; attaching eBPF replaces an existing
classic socket filter. The design cannot call `SetBPFFilter()` and then treat the
eBPF gate as a second independent filter on the same socket.
[Linux socket documentation](https://man7.org/linux/man-pages/man7/socket.7.html)

The explicit capture restrictions and selective admission policy need one composed
program. A candidate is libpcap compilation to classic BPF followed by translation
and composition with the eBPF endpoint gate. [`cbpfc`](https://github.com/cloudflare/cbpfc)
provides classic-BPF-to-eBPF translation, but socket-context compatibility, link
types, verifier acceptance, and expression equivalence require investigation.
Its availability is not proof of drop-in compatibility.

Distinguish explicit user restrictions from automatically generated RTP ranges.
The latter would be replaced by endpoint admission; an explicit restriction must
not be silently bypassed because an endpoint was learned from SDP.

Independent packet selection also remains relevant. Current paths can select
media directly using applicable IP/CIDR filters without an unambiguous SIP owner.
Those selectors need an admission alternative. Separate exact-address and
longest-prefix-match maps are candidates, updated on configuration changes rather
than call activity. Their combination and expiry must preserve the existing
selector semantics. Kernel membership never replaces authorization, expiry,
filter provenance, or final userspace attribution.

Per-call updates remain map-only. Changes to arbitrary operator BPF expressions
are a separate configuration operation whose composition and replacement semantics
remain to be designed.

## Signaling, fragments, and encapsulation

Admit supported signaling and discovery paths independently of media membership,
without implementing full SIP parsing in the kernel. The second opinion's rule
of passing non-UDP traffic and admitting UDP only by signaling port or endpoint
lookup is not sufficient for all currently supported traffic:

- Non-initial IPv4 fragments retain the UDP protocol identifier but have no UDP
  header to inspect. Dropping them prevents SIP/SDP reassembly. Existing
  [VoIP capture filters](../../internal/pkg/voip/filter.go) explicitly account for
  fragments; IPv6 fragmentation and extension headers also need handling.
- [Userspace capture](../../internal/pkg/capture/capture.go) decapsulates VXLAN.
  Its outer UDP/4789 endpoints do not match inner SIP ports or SDP endpoints.
  Supported tunnels therefore need explicit admission or bounded kernel parsing.
- Passing native ESP preserves its userspace decapsulation path, but does not
  solve ESP carried inside VXLAN. Broad ESP admission also receives encapsulated
  media, reducing the potential savings for such traffic.

Passing all non-UDP traffic includes unrelated TCP and ESP traffic, not just SIP.
Both [hunter](../../cmd/hunt/voip.go) and [tap](../../cmd/tap/tap_voip.go) already warn
about the cost of capturing all TCP. Broad non-UDP admission can be a compatibility
choice within explicit capture restrictions; it must not be described as cheap
without evidence from the deployment.

Apply endpoint rejection only where the UDP headers and observation scope can be
interpreted reliably. Define supported fragment and encapsulation paths explicitly,
including any broader reception they require. Preserve explicit operator capture
restrictions throughout.

## Proposed operator interface

The working flag name is **`--rtp-ebpf`**, defaulting to false. This is a proposal,
not an existing command option:

```text
lc hunt voip --rtp-ebpf [other options]
lc tap voip --rtp-ebpf [other options]
```

Provide an equivalent YAML setting following existing command configuration and
precedence conventions. Exact keys remain to be selected.

| Configuration                                    | Proposed behavior                                            |
| ------------------------------------------------ | ------------------------------------------------------------ |
| Omitted or false                                 | Existing capture behavior                                    |
| Enabled on supported Linux live capture          | Attach eBPF admission to the existing libpcap capture socket |
| Enabled but unsupported, or initialization fails | Clear startup error                                          |
| Other commands                                   | No automatic adoption of this feature                        |

A second backend-selection flag should not be required to make this feature work.
Diagnostic shadow mode must be explicitly distinguishable from enforcement; its
exact CLI/YAML syntax remains open. In shadow mode the dynamic media gate records
decisions without rejecting media, while explicit capture restrictions remain in
effect. It must not be selected automatically after enforcement initialization
fails.

Runtime map-update failure and capacity exhaustion need an explicit policy and
telemetry; silently widening reception or silently losing selected media must not
be treated as successful operation. The startup-error recommendation does not
settle that runtime policy.

**Proposed runtime policy: open the affected scope, loudly and temporarily.**
Widening reception is not widening authorization. Broad capture is the existing
default behavior, and userspace selection, attribution and authorization still
apply to every received packet. Losing selected media can't be undone. When
admission can't be maintained for a scope, the safer default is to stop
rejecting media in that scope rather than to keep rejecting it:

- **Triggers:** a failed map update for a selected owner, an exhausted map
  capacity, or a packet form the program can't interpret reliably for that
  scope.
- **Extent:** bounded to the affected observation domain or interface, not the
  whole process, where the failure can be attributed that narrowly.
- **Visibility:** an explicit state in status and metrics, a log on entry and
  exit, and counters for the time spent open and the packets admitted while
  open. It must never look like normal operation.
- **Exit:** return to enforcement automatically once the cause has cleared,
  such as a successful retry, freed capacity, or a re-synchronized map, after
  reconciling the map with the current owner set.
- **Configurable:** an operator can choose to stay closed instead, for example
  when the host can't absorb broad capture. The choice must be explicit and
  reported in the same way.

This differs from the startup rule. An explicitly requested feature that can't
initialize still fails startup, because there is no established state to
degrade from. The fail-open policy covers degradation of a running enforcement.
It must not be confused with shadow mode, which is an explicitly selected
diagnostic mode.

## Remaining correctness and compatibility questions

- **Signaling:** Preserve configured SIP discovery, UDP signaling, and the TCP
  segments needed for reassembly. Admit signaling independently of selected-media
  membership; do not try to perform full SIP matching in eBPF.
- **Offer/answer lifecycle:** Handle delayed offers, provisional SDP, re-INVITEs,
  UPDATE, forking, rejection, hold, and disabled streams. Existing endpoint
  registration accumulates associations; replacing old endpoints immediately would
  change behavior and needs a deliberate transition policy.
- **Termination:** Follow authoritative completion, grace periods, expiry,
  eviction, and shutdown, including generation checks for reused identifiers.
- **RTP/RTCP:** Decide handling of separate RTCP endpoints, multiplexing, multiple
  media sections, and secure media without assuming every stream is one port pair.
- **Network representation:** Define behavior for NAT, asymmetric observation,
  VLANs, IPv6 extension headers, IP fragments, and encapsulation/decryption paths.
  Non-initial fragments and encrypted inner headers may not expose UDP endpoints.
  Any broader reception fallback must be explicit and bounded where applicable.
- **No-filter and independent-filter modes:** Specify admission consistent with
  existing selection semantics. Absence of a configured SIP filter must not
  accidentally become a deny-all policy.
- **Updates and recovery:** Preserve ordering across endpoint addition/removal,
  filter revocation, retries, controller shutdown, and socket recreation. Individual
  map operations do not make a multi-endpoint transition transactional.
- **Resource limits:** Bound signaling metadata, call ownership, endpoint maps,
  update work, and any retry queues; expose capacity and update failures.
- **Platform support:** Select and test kernel features, privileges, architecture
  support, and supported capture link types before documenting requirements.

These are implementation questions, not authorization for a broader capture or
protocol rewrite.

## Shadow validation and missing-media diagnostics

A shadow mode is useful, but aggregate would-reject counters cannot establish
which selected-call packets would have been lost. Validation needs correlated
decision evidence, such as bounded diagnostic events with packet identity and
policy generation, or controlled replay with reproducible state transitions.
Rechecking a live map later in userspace is not equivalent to knowing its state
when the packet reached the kernel. Evidence collection must expose its own loss
or sampling limits; sampled evidence cannot prove absence of all defects.

Interpret mismatches according to their timing:

| Packet timing/state                                          | Interpretation                                                                                    |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Before call selection                                        | Rejection is expected under matched-only admission, even if later attribution identifies the call |
| After selection but before endpoint publication              | Admission-window loss to measure, not automatically a stale-map defect                            |
| After successful publication while eligibility remains valid | An unexpected rejection needs investigation of the map, parser, scope, and policy                 |

The publication interval still needs to be minimized and characterized. Calling
it a separate category does not make arbitrary delay acceptable. Shadow mode also
observes packets that enforcement would drop, which can affect downstream state
and queue timing; compare equivalent selection/lifecycle rules and document these
differences.

Expose a metric and diagnostic log for selected, answered calls without observed
media after a configurable interval. Distinguish successful map installation from
observed candidate packets and final userspace attribution. This signal can reveal
silent loss, but it is not proof of an admission defect: capture placement, hold,
inactive streams, or genuinely absent media can also explain it. Neither timeout
expiry nor an alert should broaden capture or override authorization automatically.

## Validation and performance evidence

Proposed correctness validation:

- [ ] With the option disabled, existing hunter/tap behavior remains unchanged.
- [ ] With it enabled, ordinary call churn updates maps without replacing sockets
      or restarting capture.
- [ ] Unselected media is rejected; selected media and signaling remain observable
      within the documented admission timing and supported packet forms.
- [ ] A later match can use retained SDP without retaining pre-match RTP.
- [ ] Multiple legs, shared endpoints, repeated SDP, identifier reuse, grace
      periods, and expiry cannot delete another active owner's admission.
- [ ] Userspace ambiguity, authorization, and independent packet-filter behavior
      remain intact.
- [ ] Explicit capture expressions retain their supported meaning.
- [ ] Shared observation domains allow signaling and media on different interfaces;
      explicitly separated domains do not share admission accidentally.
- [ ] Supported fragments and encapsulated signaling/media survive admission.
- [ ] Libpcap userspace filtering, pre-attachment buffered packets, and socket
      recreation preserve the documented admission boundary.
- [ ] Shadow evidence distinguishes pre-selection packets, publication delay, and
      incorrect rejection, and exposes incomplete evidence.
- [ ] Ring ownership, shutdown, metadata, map capacity, and failure handling are
      exercised for both hunter and tap.

Measurements should compare broad capture and selective capture with the same
traffic and output requirements: admitted/rejected packet counts, CPU, allocations,
queue pressure, kernel drops, active endpoint count, update rate/failures, and
SDP-to-map publication delay. Include multiple match fractions, legs, and call
lifetimes, using 100 calls/s as one user-provided scenario.

A userspace endpoint pre-filter is an optional comparison, not a required interim
feature. It still needs minimal header and scope parsing before full decoding and
queueing, and cannot remove receive-ring pressure. Build it only if the comparison
is useful enough to justify its separate implementation and maintenance.

The recommended progression is a libpcap attachment/ownership implementation with
explicit shadow diagnostics, followed by enforcement in a controlled deployment
and broader use based on observed correctness. A direct AF_PACKET backend remains
contingent on a concrete need rather than a mandatory next stage.

Report any initial media loss and unsupported packet forms alongside resource
savings. No throughput, latency, CPU, or memory threshold was agreed during this
brainstorm; exploratory measurements must not be converted into invented release
gates.

## Review (2026-10-02)

> The following second opinion is preserved as review input. The main report
> incorporates the assessment below; statements in this original review are not
> all adopted unchanged.

The design fits deployments where media dominates the captured traffic and only a
small fraction of calls is selected. There, userspace currently receives and
inspects every media packet only to discard nearly all of them, and admission in
the kernel would remove most of that work. The choices that matter are sound:

- **Hook.** A socket filter rather than XDP leaves host traffic untouched.
- **Updates.** They are map-only, with no capture restart.
- **Authority.** Selection, attribution and authorization stay in Go.
- **Map.** A bounded hash map with explicit errors, rather than LRU eviction.
- **Activation.** Explicit opt-in, with a startup error instead of a silent
  fallback.
- **Matching.** It is per endpoint, checking source or destination, so one side
  behind NAT or latching still matches when the other side's endpoint is in the
  SDP.

Points to add or weight differently:

1. **Don't make capture scope per interface by default.** Signaling and media of
   one call can arrive on different capture interfaces, for example when traffic
   is mirrored through several sessions. If the interface is part of the key,
   media arriving on another interface than its SDP is rejected. Make the scope
   configurable, default it to all capture interfaces of the process, and share
   one map across their sockets.

2. **Detect selected calls that receive no media.** A defect in map maintenance
   turns into silent loss of content for exactly the calls that were selected,
   and nothing else would show it. Beyond map capacity and update errors, track
   selected and answered calls that have no admitted media after a configurable
   interval. Expose this as a metric and log it, so it can be alerted on.

3. **Introduce the filter in a shadow mode first.** Attach the program in a mode
   that only counts what it would reject, while broad capture continues. Compare
   that against userspace attribution: every packet userspace attributes to a
   selected call that the map would have rejected is an admission defect. This
   allows validation on real traffic before the filter enforces anything.

4. **Account for queueing delay in admission timing.** Signaling shares the
   receive ring and the userspace queues with media. Under heavy load, a backlog
   of media can delay SIP processing, and therefore map installation, by much
   more than the block retirement timeout, so the first media of a selected call
   can be lost. Once enforcement is active, the queues carry little besides
   signaling and selected media, which largely removes this. It still applies at
   startup, in shadow mode, and in any partial or fallback operation. Measure
   SDP-to-map delay under load, not only on an idle system.

5. **Give independent selectors their own admission path.** Address and prefix
   selectors don't depend on SDP. Admit them through a separate static map,
   with a longest-prefix-match map for prefixes, updated when the configured
   filters change rather than per call.

6. **Admit signaling without parsing it in the kernel.** Signaling can arrive
   over TCP on arbitrary ports, in IP fragments, or inside ESP with a null
   cipher. A simple and robust rule is to pass all traffic that isn't UDP, and to
   admit UDP only by configured signaling port or by a map hit. Signaling volume
   is small compared with media, so this costs little.

7. **Prefer the smaller backend change first.** Replacing the capture backend
   carries most of the risk: timestamps, VLAN metadata, drop counters,
   decapsulation, shutdown and statistics. Attaching the eBPF program to the
   existing libpcap socket (`pcap_fileno` plus `SO_ATTACH_BPF`) keeps that path,
   provided nothing calls `pcap_setfilter` afterwards. It still needs a binding
   update or a small adapter, but a much narrower one. Move to a native
   AF_PACKET backend only if this proves insufficient.

8. **Measure a userspace pre-filter as a baseline.** An endpoint lookup right
   after capture, before decoding and queueing, saves much of the userspace work
   without kernel code, though not the receive-ring pressure. It shows how much
   of the gain only the kernel stage provides, and it is a smaller interim step.

Suggested order: the userspace pre-filter as a baseline, then the eBPF filter in
shadow mode together with the "selected without media" signal, then enforcing
mode on a single deployment, then wider use.

## Review assessment (2026-10-02)

The second opinion strengthens the proposal and changes the preferred integration
to libpcap-first. Its findings are reconciled into the main report as follows:

| Review point                    | Assessment                                                                                                                                                                        |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Shared scope                 | Adopt sharing within an observation domain; preserve explicit isolation for overlapping address spaces. Signaling interface identity alone must not constrain media.              |
| 2. Selected calls without media | Adopt configurable diagnostics, but treat absence of media as a signal to investigate rather than proof of a filter defect.                                                       |
| 3. Shadow mode                  | Adopt with correlated, timing-aware evidence. Aggregate counters and retrospective attribution are insufficient for the proposed packet-level correctness claim.                  |
| 4. Queueing delay               | Adopt end-to-end measurements under load; enforcement reduces unrelated traffic but does not eliminate all possible backlog.                                                      |
| 5. Independent selector maps    | Adopt as the candidate design, preserving configuration, expiry, and combination semantics.                                                                                       |
| 6. Non-UDP bypass               | Qualify: fragments and VXLAN require explicit handling; passing all non-UDP traffic can be costly and remains subject to explicit capture restrictions.                           |
| 7. Libpcap first                | Adopt. Attachment must coordinate userspace filter state, startup buffering, socket recreation, and explicit capture expressions, not only prohibit later `pcap_setfilter` calls. |
| 8. Userspace baseline           | Optional experiment, not a mandatory implementation stage or acceptance gate.                                                                                                     |
