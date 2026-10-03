# First-Wave Structured Log Expansion

**Date:** 2026-10-03
**Status:** Complete; verified and committed with implementation
**Scope:** DHCPv4, NTP, known-host and known-service events and structured logs
**Research:** [Zeek-style log expansion assessment](../research/zeek-log-expansion-assessment.md)
**Related proposal:** `/home/grischa/declarative-protocol-service-detection.md`

## Outcome and sequence

Add `dhcp.log`, `ntp.log`, `known_hosts.log`, and `known_services.log` using the
implemented event platform. The same typed observations must work in hunter
event mode, processor packet analysis, tap, sniff, and local/offline/remote TUI
paths. Event production must not depend on enabling file logging.

Implement DHCP/NTP first, then bounded inventories. This is the initial subset
of the research's broader first wave. Software, traceroute, tunnel, reporter,
notice, and deeper protocol logs are deferred. The next independent project can
be the declarative proposal's STUN/DNS classification slice; completing the
whole Zeek roadmap is not a prerequisite.

Use Go parsers with stable typed outputs now. A later declarative detector may
replace recognition/extraction only when it preserves those outputs and passes
the same tests. Do not introduce YAML compilation, feeds, service-classification
lifecycles, `PortHints()` refactoring, new protocol-specific CLI commands, or
rule-bundle distribution in this plan. Known services means observed network
endpoints and protocols, not application labels such as WhatsApp.

## Existing implementation to extend

| Responsibility | Current integration points |
|---|---|
| Shared producers and lifecycle | `internal/pkg/eventanalysis/runtime.go`, `mapping.go`; runtime callers in hunter, processor, sniff, TUI, and remotecapture |
| Existing recognition | `internal/pkg/detector/signatures/application/dhcp.go`, `ntp.go` |
| Typed events and delivery identity | `internal/pkg/events/`, including `identity.go` exhaustive switches |
| Wire contract and validation | `api/proto/events/v1/events.proto`, `api/gen/events/v1/`, `internal/pkg/events/protoadapter/` |
| Capabilities and ingress | Hunter connection manager/client; processor registration handlers, event ingress/service, upstream manager/router |
| Canonical output | `internal/pkg/logschema/`, `internal/pkg/logstream/records/`, processor and sniff sink registrations |
| Query and presentation | `internal/pkg/eventquery/projection.go`, `internal/pkg/tui/event_view.go`, `components/eventsview.go` |
| Connection evidence | `internal/pkg/conntrack/tracker.go`, `events.ConnEvent` |
| Configuration | `internal/pkg/logflags/`, role configs and runtime construction paths |

RADIUS is a recent example of adding a typed observation throughout this stack.
Reuse existing identity, bounded dispatch, spool/WAL, authorization, relay,
rotation, and TUI infrastructure. The current generic detector metadata map is
not a sufficient canonical producer interface.

## Decisions for this wave

### Record granularity and identity

DHCP and NTP emit one typed event and one log record per accepted protocol
message. Bounded association adds context to later messages without rewriting
earlier records or waiting for a completed session. This deliberately differs
from transaction-aggregated output; document the difference from Zeek. Do not
put these message streams through transaction coalescing that discards messages.

Keep the actual observed flow, UID, Community ID, capture scope, and source
provenance. DHCP broadcasts, address changes, and relays can span multiple flows:
do not manufacture a shared flow UID for the whole address-assignment exchange.
Use a separate scoped exchange/association identifier when correlation succeeds.
Do not confuse protocol retransmission with transport retry: both observed
datagrams remain observations, while retries of an already-produced event retain
its delivery identity and follow existing ingress deduplication.

Inventory events retain the qualifying connection's envelope as evidence, with
the subject host/service in separate fields. The current wire validator requires
valid flow addresses and a protocol; no synthetic endpoints or general non-flow
envelope extension are needed for these evidence-backed records.

### DHCPv4

Create a bounded typed decoder shared by detection and runtime production,
preferably under `internal/pkg/dhcp/`. Preserve existing detector behavior where
valid, but do not equate a cached protocol label with a parsed new message. The
current signature caches results and silently stops at malformed option lengths;
the new observation path must parse each accepted datagram and expose incomplete
input explicitly.

The initial field contract covers operation/message type, transaction ID,
hardware type/address, optional client identifier, client/offered/next-server/
relay addresses, server identifier, requested address, hostname/domain, lease,
router/DNS lists, parameter-request list, association status/ID, and partial or
truncated state. Keep BOOTP next-server address separate from DHCP server
identifier. Preserve binary identifiers safely with bounded byte representation;
do not assume every client identifier is a printable string or MAC address.

Use the actual UDP envelope and derive message roles from the decoded fields.
Key bounded association by capture authority/epoch, client identity, transaction
ID, and relay context, retaining server distinctions. Preserve unmatched and
ambiguous observations; never attach a response using transaction ID alone.
Support discover/offer/request/ack/nak plus observed decline/release/inform
messages without promising complete lease history. Association expiry/eviction
must not suppress current message output.

DHCPv6 and bare BOOTP are out of scope for `dhcp.log`; existing BOOTP detection
must continue working. Validate options, padding/end handling, overloaded option
areas, and repeated-option behavior with bounded readers before publishing the
schema. Do not dump unknown/vendor option bytes into routine logs. Protocol
references: [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html) and
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html).

### NTP

Create a typed fixed-header decoder, preferably under `internal/pkg/ntp/`, and
reuse it from the detector and runtime. Support the standard time-message
header; explicitly exclude control/private formats from time-message decoding.
Preserve version, numeric mode/leap indicator, stratum, signed poll/precision,
root delay/dispersion, raw reference ID, and reference/origin/receive/transmit
timestamps. Reference-ID interpretation must depend on its context, not assume
it is always an IPv4 address. Use exact wire values where conversion would lose
meaning; define zero/unavailable timestamps and era resolution relative to
capture time before exposing converted times.

Add bounded request/reply association for client/server messages using source
scope, endpoints, and echoed request timestamp. Ambiguous, unmatched, broadcast,
and symmetric observations still produce independent records with truthful role
and association fields. Do not claim server authentication or calculate a
client clock offset from sniffer wall-clock timestamps. Authentication checks,
NTS, control/private analysis, and clock-quality conclusions are out of scope.
Reference: [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html).

### Known hosts and services

Add a small bounded inventory component, preferably `internal/pkg/inventory/`,
called from locally produced `ConnEvent`s in the shared runtime. Cover every
connection-summary path: expiry, eviction, EOF, reset, and close. Event-mode
ingress relays inventory events already produced by the source; it must not
derive them again. This first version emits when a qualifying connection summary
is available, not immediately on the first handshake packet. Document this delay.

Introduce explicit inventory enablement and validated local CIDRs; there is no
existing local-network policy to reuse, and `ConnEvent.LocalOrigin` and
`LocalResponse` are not currently populated. Enabled inventory requires a
nonempty explicit policy. Do not silently classify all RFC1918 space or every
observed Internet address as local. Match both IPv4 and IPv6, normalize addresses,
and exclude unspecified, multicast, and broadcast subjects.

Known-host evidence is an observed completed TCP handshake or both directions
of a UDP exchange. A lone SYN, destination address, or DHCP offered address
does not establish a known host. Evaluate each qualifying local endpoint.
Known-service evidence additionally requires a reliably oriented responder,
responder port, and a recognized protocol supported by actual analysis. A port
hint or generic cached label alone is insufficient. For UDP, require decoded
request/response roles and successful association; start with validated existing
DNS and the new NTP/DHCP paths where endpoint semantics permit it. A broadcast or
relay address must not become a client service. Leave unsupported or ambiguous
service cases absent rather than inventing certainty.

Use an explicit finite evidence enum on derived events. If existing connection
summaries cannot prove a condition, add the minimum internal evidence plumbing
from the parser/tracker; do not infer handshake success from arbitrary packet
counts or a partial flow's summary label. Partial capture scope remains visible
even when enough positive evidence exists for an inventory observation.

Deduplicate hosts by scope plus subject address, and services by scope plus
responder address, port, transport, and protocol. Scope includes origin node,
producer/capture epoch and capture source/interface or offline input identity.
Do not merge independent sensors just because their private IPs match. Emit the
first qualifying observation in a configurable retention window; after expiry
or eviction a subsequent qualifying observation may emit again. Bound entries
and retained bytes globally and per scope, with deterministic expiry/eviction
and counters. This is a bounded observation inventory, not persistent asset
identity or a guarantee of one record forever.

Use capture-time watermarks for offline expiry and deterministic ordering.
Out-of-order input must not move the watermark backward or revive expired
state. Reset/producer-session changes clear correlation and dedup state. Include
effective inventory policy and analysis revision in offline session identity;
live policy changes follow existing producer-session boundary semantics.

### Configuration, privacy, and compatibility

Keep the existing default seven log streams unchanged in this wave. Expose the
four additions through explicit `--log-streams` selection. Generic event
subscribers can receive new supported protocol kinds; inventory additionally
requires its producer policy. Do not advertise enabled inventory production
when its configuration is absent. Selecting an inventory log requires compatible
local policy for local analysis or compatible inventory-producing event sources.
Hunters must receive equivalent operator configuration through their normal
configuration path; new remote rule/config distribution is not part of this plan.

Define shared config keys for local CIDRs, inventory enablement, entry/byte caps,
retention, and DHCP/NTP association caps/timeouts, then wire all runtime callers.
Choose and document practical finite defaults during contract implementation;
they are configuration choices, not performance acceptance targets. Validate
invalid/zero/negative limits consistently and avoid allocating disabled inventory
state. Local CIDRs classify inventory subjects, not packet-capture eligibility.

DHCP names, hardware/client identifiers, and inventory details can be sensitive.
Define a per-field subscriber projection using the existing sensitive-field
policy. Log enablement is explicit; document local file handling. Do not export
opaque options or credentials. Internal correlation may use an identifier even
when the subscriber projection omits it. Projection must not mutate shared events.

Append event kinds/payloads without renumbering existing fields. Distinguish
supported kinds from kinds required by configured consumers. Older peers must
continue existing workloads when new kinds are not required. If a requested
stream cannot be supplied, reject or use the existing explicitly configured
packet fallback; never silently report success while omitting it. Preserve
unknown-field behavior and report unsupported optional kinds as compatibility
loss. Do not rebuild the event spool or weaken acknowledgement boundaries.

## Implementation checklist

### 1. Contracts and fixtures

- [x] Specify canonical field names/types/order and unset/partial semantics for
      all four streams in `docs/structured-protocol-log-schema.md`; distinguish
      message records from Zeek transaction/session output.
- [x] Define typed DHCP/NTP observations, association/evidence enums, inventory
      subject fields, sensitive-field policy, config keys/defaults, and source
      scope rules described above. Keep protocol IDs independent of display text.
- [x] Add synthetic positive/negative fixtures with expected semantic records:
      DHCP broadcasts/relays/retransmits, NTP roles/timestamps, and TCP/UDP
      inventory evidence. Reuse repository fixture conventions.
- [x] Record the schema/profile compatibility decision and expected old-peer
      negotiation behavior before adding new wire kinds.

### 2. Protocol producers

- [x] Implement safe typed DHCP decoding and bounded association; make the current
      signature reuse validated extraction without breaking BOOTP recognition.
- [x] Implement safe typed NTP decoding and bounded association; separate time
      messages from unsupported formats and remove incorrect numeric heuristics
      from the accepted typed path when protocol validation requires it.
- [x] Integrate both into `eventanalysis.Runtime` for every accepted datagram,
      independent of detector cache hits and sink enablement. Reuse decoded packet
      input where available; avoid duplicate per-message parsing.
- [x] Wire configuration, capture-time expiry, reset/EOF/close, statistics, and
      partial behavior. Keep association loss distinct from dropped events.
- [x] Add normalized events, constructors, immutable ownership/cloning, and every
      identity-assignment/type switch required by the new kinds.

### 3. Protocol delivery and output

- [x] Extend protobuf enums/payloads and regenerate with `make -C api/proto`.
      Update adapters, validation, typed-nil handling, and unknown-kind behavior.
- [x] Update advertised/required lists in hunter connection manager/client,
      processor registration/ingress/service, and upstream manager/router. Prefer
      shared kind mappings where they remove repeated literal ID lists without
      conflating supported, enabled, and required capabilities.
- [x] Add canonical schemas/records/goldens, processor and sniff sink mappings,
      dispatcher registrations, and stream validation/help. Preserve defaults
      and pass message events through coalescing unchanged.
- [x] Extend query projection, summaries, filters, TUI kind rendering, and relevant
      scopes. Keep TUI rendering read-only and reuse its existing refresh chain.
- [x] Extend subscriber sensitive-field projection and test authorized/omitted
      fields in direct subscription and relay paths.
- [x] Prove DHCP/NTP parity through the path matrix below before inventory work.

### 4. Inventory production and output

- [x] Implement explicit local-network policy and qualifying evidence extraction;
      populate connection local-endpoint flags consistently where applicable.
- [x] Implement bounded per-scope host/service deduplication with capture-time
      expiry, counters, and documented eviction/re-emission behavior.
- [x] Produce inventory events only from local runtime connection summaries,
      preserving source evidence, timestamp, identity, and partial scope.
- [x] Include policy in offline identity and wire settings through hunter,
      processor/tap, sniff, TUI, and monitoring-client runtime constructors.
- [x] Extend the same event/API/capability/schema/sink/query/TUI surfaces used by
      DHCP/NTP for the two inventory kinds; require enabled producer policy.
- [x] Verify EOF/reset/close behavior and that event ingress/upstream relay never
      creates a second inventory observation from an already-derived source.

### 5. Validation, documentation, and completion

- [x] Run the focused correctness tests and path matrix below, including race
      tests for newly shared state and compatibility tests for old peers.
- [x] Run `make test`, `make vet`, and builds for affected all/hunter/processor/
      tap/cli/tui roles; include LI-tagged regression coverage without adding new
      LI selection or delivery behavior. Ask if testing needs sandbox escalation.
- [x] Update structured-log guides, schema contract, command help/examples,
      configuration reference, and the research baseline to reflect implemented
      streams and their explicit limits.
- [x] Update affected English manual content and every translation configured
      in `docs/manual/languages.json`, resolve affected fuzzy entries, and run
      `make manual-check` and `make manual`.
- [x] Format changed files, verify each completed item, check off this plan, and
      commit implementation and plan updates together. Do not mark missing or
      deferred behavior complete merely because a log file is produced.

## Validation matrix and completion evidence

| Area | Required evidence |
|---|---|
| DHCP parser | Short headers, bad cookie, malformed/overloaded/repeated options, binary identifiers, field bounds, unknown options; no panics or silent complete records from malformed input |
| DHCP association | Same XID/different clients or sensors, multiple servers, relay traffic, retransmits, unmatched/ambiguous replies, expiry/eviction, address changes; no false merging or loss of independent messages |
| NTP parser/association | Signed and fixed-point fields, zero/era-boundary timestamps, stratum/reference-ID variants, unsupported modes, bounded extensions, duplicate/unmatched timestamps, reversed direction and scope isolation |
| Inventory | Positive handshake/validated UDP evidence; reject lone SYN/one-way/port-only evidence, nonlocal/special addresses, ambiguous responders; IPv4/IPv6 policy, cap/window/reset/ordering tests |
| Contract | Every new kind round-trips identity, optional fields, binary values, direction, provenance and partial state; reject oversized/invalid input; preserve unknown fields and existing kinds |
| Delivery | Retry/reconnect identity, one derivation at origin, two-hop relay, required-versus-optional old-peer behavior, reliable and memory profiles, explicit omission/loss and subscriber privacy |
| Output/UI | TSV headers and JSONL goldens, query filters/details/summaries, explicit stream selection, unchanged defaults, no unintended coalescing, ring eviction distinct from transport loss |
| Resource/lifecycle | Enforced configured state/input caps, bounded live queues, offline lossless drain, no leak across EOF/reset/close, subscriber pressure isolated from capture |

Run equivalent fixtures through direct runtime, sniff logs, processor packet
mode, hunter event mode to processor, tap, local/offline TUI, remote event
subscription, monitoring packet fallback, and processor hierarchy. Compare
semantic fields while explicitly accounting for intended origin/session/scope
differences. Ensure inventory policy is equal for parity comparisons. Regression
coverage must show events are available when log output is disabled.

Use targeted `go test -tags all` package tests during development and the project
entry points above for final verification. Measurements of CPU, allocation,
throughput, and occupancy may guide implementation, but this plan creates no
new numerical performance gate. Correctness, privacy, durability, expiry, and
configured resource-limit enforcement remain required.

Completion means all four opt-in streams and their typed events are usable
through the supported paths, with documented field/coverage limits and passing
validation. No YAML compiler or application classifier is needed to close this
wave. Follow-on classification consumes stable observations rather than making
the log sinks depend on a future rule language.

## Completion evidence (2026-10-03)

All four opt-in streams and their shared-runtime producers are implemented.
DHCP/NTP emit independent messages. Inventory derives once from local connection
summaries with explicit policy, positive evidence, bounded deduplication, and
capture-time lifecycle handling. The default seven streams remain unchanged.

Focused correctness and race checks passed for parsers/associations, wire
identity/ownership, privacy and mixed-version delivery, actual IPv4/IPv6 and
link-local TCP handshakes with parsed HTTP, matched DNS/NTP/DHCP UDP evidence,
negative evidence, disabled-state allocation, cap/retention/order handling, and
expiry/eviction/EOF/reset/close. Actual TSV and JSONL writer goldens cover all
four streams. Queries, TUI details/scopes, and message coalescing checks passed.

The shared path matrix passed under race detection for sniff with logs enabled
and disabled, hunter spool recovery, processor packet/tap analysis, two-hop
relay/retries without re-derivation, monitoring fallback/subscriptions, and local
live/offline TUI including the offline indexer. Three-node registration tests
verify truthful inventory production guarantees while preserving optional-kind
compatibility. Recovery tests preserve pending identities across unchanged
policy and require a new drained session when effective policy changes.

Final required commands passed: `make test`, `make vet`, `make all hunter
processor tap cli tui`, `make build-li processor-li tap-li verify-no-li`, and
LI-tagged affected runtime/connection/inventory/hunter/tap regressions. LI core,
delivery, X1/X2X3, and processor regression packages also passed. Required tests
ran outside the sandbox with explicit user authorization; securestore ownership
checks were preserved.

English and German manuals passed `make manual-check` (5504/5504 translated
messages) and `make manual`, including cross-language consistency validation.
Changed Go files were formatted and `git diff --check` passed.

The bounded closure review is **CLOSED**. Its five scoped findings were repaired
and verified: disabled evidence allocation, recovered analysis-policy identity,
relay production guarantees, decoded truncation, and link-local service policy.
No deferred requirement or invented performance gate remains for this wave.
Implementation, documentation, and this checked plan are committed together.
