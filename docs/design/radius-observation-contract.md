# RADIUS observation and association contract

Date: 2026-09-08. Profile: `radius-poi-v1`.

This is the implementation contract for [Phase 0](../plans/radius-poi-implementation.md),
paired with the [identity contract](radius-identity-contract.md). It defines local
acceptance behavior; it does not assert receiving-MDF agreement or production
interoperability. Runtime implementation belongs to Phases 1–7.

## Observation and ownership

Analyze visible UDP with either endpoint on configured service ports, default
1812 and 1813; explicitly configured ports add to that set. Supported codes are
1, 2, 3, 4, 5, and 11. Classify client/server roles by request/response code,
never by assuming that NAS attributes equal transport addresses. Require a
complete UDP datagram, a RADIUS Length of 20–4096 within its payload, and fully
validated attribute boundaries. Bytes after RADIUS Length are padding, excluded
from the message but retained in packet outputs. Unknown attributes remain opaque;
vendor 3561 sub-attribute structure must be fully validated before any identity
match. The identity contract specifies other attribute validation details.

The shared, non-LI observation has these logical fields (wire/API representation
is Phase 1/3 work):

| Field       | Contract                                                                                                                                                              |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Capture     | Original UTC timestamp, original link type, captured/original lengths, observation ID                                                                                 |
| Scope       | Authenticated origin node ID, capture epoch, interface/source ID, configured operator scope/profile revision                                                          |
| Endpoints   | IP family, source/destination IP and UDP port; separate client/server tuple                                                                                           |
| Message     | Code, Identifier, declared Length, 16 original Authenticator bytes, exact validated message bytes                                                                     |
| Attributes  | Ordered type/value byte instances including repeats and unknowns; VSA outer bytes plus validated vendor/sub-attribute instances                                       |
| NAS fields  | Optional NAS-IP-Address, NAS-IPv6-Address, NAS-Identifier and line fields, separate from endpoints                                                                    |
| Association | Status, opaque request-instance ID if known, originating request observation ID, request first-seen time                                                              |
| Evidence    | Separate direct and inherited references: target kind, complete criterion group, filter ID/revision, authoritative task/generation binding and scope/profile revision |

Observation IDs and request-instance IDs are independent of the eight-bit RADIUS
Identifier; use a capture epoch plus monotonic 64-bit local sequence, never reuse
a sequence in an epoch. Generate an unpredictable 128-bit epoch on opening a
capture source. A restart, source reopen, capture gap, or hunter transport
reconnect starts a new epoch and discards association state. Interfaces and
independent readers never share an epoch. Upstream relays preserve origin scope
and IDs, and cannot substitute their own scope. Offline replay assigns a fresh
epoch per reader invocation; fixture symbolic scopes stand in for those epochs.
Missing or untrusted scope prevents inherited LI attribution. Reconnect queues
from an old epoch cannot be relabeled as new evidence.

Copy packet/message and attribute storage before capture-buffer reuse; asynchronous
consumers receive immutable owned storage or their own deep copy. Evidence slices
are immutable too. Do not import LI implementation types into the shared package.
Processor admission validates bytes, scope, criterion completeness and current
generations; a transported filter ID alone is insufficient. Decoding and matching
do not wait for output I/O. Ordinary sinks retain their own selection and queues.

## Fragments and validation outcomes

Reject every IPv4 datagram with MF set or a nonzero fragment offset, and every
IPv6 packet containing a Fragment header, including atomic fragments. Do not
attempt RADIUS decode or attribution on a first fragment. No reassembly is in
this profile. Generic independently selected packet sinks may still retain all
fragments unchanged. Capture BPF for such generic sinks must itself include
fragments; a port-only BPF cannot promise their capture.

At the first analysis ingress, give each attempted observation one validation
outcome: `valid`, `fragmented`, `malformed`, or `unsupported`. Apply fragment
classification before UDP/RADIUS validation; unsupported transports/codes are
outside this profile, malformed lengths/truncation are malformed. Fragment
counts include visible fragments in the configured capture scope even where no
UDP port is available. Invalid observations carry diagnostics but no identity
or LI evidence. Re-decoding downstream must not increment origin counters again.

The correlator separately owns request/retransmission counts and one response
status per valid response: `unique`, `missing`, `ambiguous`, `expired`,
`incompatible`, or `capacity_suppressed`. Direct matches are orthogonal to these
statuses. LI admission owns stale-generation rejection; sinks own their drops
and delivery outcomes. Counters count observations unless explicitly named as
state-entry events (expiration/eviction), and have bounded labels.

## Bounded observational association

The key is full capture scope, IP family, client IP/port, server IP/port and
Identifier. Access-Request can associate only with Access-Accept, Access-Reject,
or Access-Challenge; Accounting-Request only with Accounting-Response. A challenge
does not authorize the next Access-Request: that is another exchange. Authentication
does not authorize subsequent identity-free accounting.

Within a key, compare the entire validated request message, including Code and
Authenticator. Identical bytes within retention are retransmissions of one
instance. Different bytes are distinct candidates, even if one has no matching
filter or uses another code family. Keep every competing valid request visible
before application rejection. Response Authenticator bytes are retained, but no
shared secret is configured and they cannot select an owner.

This is observational association, not cryptographic authentication. RADIUS
authenticator checking requires information unavailable to this observer; see
[RFC 2865](https://www.rfc-editor.org/rfc/rfc2865.html). A unique compatible request
is only unique among observed candidates within the configured retention horizon.
Spoofing, unobserved requests and late traffic cannot be ruled out. Deployments
requiring cryptographic or unbounded historical certainty are unsupported.

| Setting                       | Default and allowed bounds                                                                                 |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Request lifetime              | 30 seconds from first observation; 1–300 seconds                                                           |
| Quiet guard                   | Equal to configured lifetime; cannot be shorter                                                            |
| Cleanup interval              | 1 second; expiry also checked synchronously on lookup                                                      |
| Total request candidates      | 65,536; 1–1,048,576                                                                                        |
| Candidates per key            | 4; 1–16                                                                                                    |
| Candidate storage byte budget | 64 MiB including copied messages/evidence; 1–1,024 MiB                                                     |
| Suppression keys              | 65,536; 1–1,048,576                                                                                        |
| Total correlator state budget | 96 MiB including candidates, maps, guards and evidence; 2–2,048 MiB and greater than candidate byte budget |
| LI correlation allocation map | 65,536 entries and 16 MiB, whichever is reached first; 1–1,048,576 entries and 1–256 MiB                   |
| Pending response storage      | Zero                                                                                                       |

Use an injectable monotonic observation clock for live expiry. Offline replay
uses nondecreasing `max(previous, packet timestamp)` logical time; preserve the
original timestamp separately. Retransmissions do not extend request lifetime.
Retain candidates after responses until expiry, so a duplicate response can reuse
the same instance and a later competing request cannot erase earlier ownership.
Any multiple distinct candidates for a key conservatively suppress inheritance,
even across code families. Do not combine criteria across candidates or tasks.

After expiry, eviction, or per-key candidate overflow, keep a suppression key
until a full quiet guard has passed with no request or response on that key.
Activity extends this guard; dropping one candidate must never make a remaining
candidate uniquely eligible. While suppressed, direct matching remains possible,
but requests do not establish inheritable state. Expiry guards produce `expired`,
collision guards `ambiguous`, and capacity-loss guards `capacity_suppressed`.
If the suppression table or total byte budget cannot retain necessary guards,
clear candidate state and suppress inheritance globally until a full quiet guard
with no in-scope valid RADIUS traffic. This constant-size fallback trades
availability for bounded memory and safety. Count each capacity loss once.
Account all map entries, evidence and guard storage against the total state
budget; do not hide unbounded owner lists behind a count cap. Reject invalid
configuration rather than silently clamping limits.

Responses observed before requests get `missing`; retain no pending response and
never revisit its authorization after a request appears. Incompatible single
candidates give `incompatible`. Direct response criteria can independently
authorize the response, but cannot turn an ambiguous inherited owner into a valid
one. Request-time matches are a snapshot: later task activation/modification
cannot retroactively populate them. At response admission, all inherited criteria
must still belong to the same current task generation and deployment scope.

## Duplicate delivery and MDF acceptance profile

Every captured valid matching datagram is an independent delivery opportunity,
including retransmissions and duplicate mirrors. Ordinary output is also per
observation. There is no cross-interface deduplication or durable exactly-once
guarantee. A task matching directly and through inheritance receives at most one
PDU for that observation. Independent tasks receive their own PDUs. Existing
delivery retry/sequence behavior remains applicable; retrying a serialized PDU
does not assign it a new correlation value or sequence.

For local acceptance, X2 uses payload format 11 and exactly the original validated
RADIUS message, excluding Ethernet/IP/UDP and padding. The existing fixed header
encodes Correlation ID as eight bytes in network byte order and Payload Direction
Unknown as 1; see [pdu.go](../../internal/pkg/li/x2x3/pdu.go) and
[ETSI TS 103 221-2 V1.10.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.10.01_60/ts_10322102v011001p.pdf).
The exchange lifetime and allocation rules below are this service profile's
choices, not claims that ETSI prescribes RADIUS session correlation.

Allocate a nonzero monotonically increasing 64-bit correlation value per request
instance at the authoritative LI encoder, scoped by configured NFID/IPID.
Persist reservation of counter ranges before use, skip unused reserved values
after crash, and never wrap. Allocation/persistence failure rejects X2 delivery
with a counter, while ordinary outputs continue. Resetting allocator storage
requires a new configured NFID/IPID identity. Multiple encoders sharing NFID/IPID
must share the allocator; otherwise reject that deployment configuration.
This gives explicit restart behavior without treating an eight-bit Identifier or
a truncated hash as a unique session ID.

Reuse the allocation for request retransmissions and uniquely associated responses
within retained request lifetime, across independent task XIDs. Keep a bounded
mapping from request-instance ID to allocation for that lifetime. If mapping
capacity is exhausted, reject affected X2 delivery rather than mint inconsistent
IDs. Retention uses the originating request's first-seen deadline, not delayed
encoder arrival. A queued request/response arriving after that deadline is
ineligible for exchange-scoped X2; reject it rather than recreate an expired
allocation. Never fall back to an orphan allocation for expired inherited
evidence. Serialized delivery retries already carry their allocation and do not
need this map. A directly matched request suppressed from association state, or
a directly matched orphan/ambiguous response, gets its own observation-scoped
allocation and cannot claim a request relationship. New epochs, new request
instances, and post-expiry observations never reuse old values. No cross-exchange,
subscriber-session, authentication-to-accounting or X3 correlation is asserted.
Payload Direction remains Unknown for both directions of transport. Transport
endpoints and capture timestamps are conveyed independently.

The receiving MDF must explicitly accept exchange-scoped correlation, eight-byte
encoding, retention, duplicates, orphan handling and Unknown direction before
deployment. No MDF identity, receiver, or agreement was supplied for this work.
That agreement is pending; the local fixture profile permits decoder and ordinary
output work but does not satisfy external sign-off or Phase 5 interoperability.

## Acceptance evidence and remaining boundary

The [synthetic fixtures](../../testdata/radius/README.md) define expected wire
observations and raw X2 payloads. They are acceptance inputs for future runtime
tests, not proof that the runtime already implements this contract. The Phase 0
plan records what was actually verified and leaves external agreement open.
