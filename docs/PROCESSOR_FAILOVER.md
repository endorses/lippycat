# Processor failover, relay handover, and reliable packets

Hunters can use an ordered list of processors with one active connection. This is
useful for redundant capture endpoints and hierarchical deployments with
intermediate relay processors. LI is optional. A common upstream can keep analysis
in one place; an endpoint list does not replicate analysis state between independent
processors.

## Choose the delivery contract

| Profile                                   | Retention and acknowledgment                                                                                                                 | Suitable topology                                                                                 |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Default raw packets, `best-effort`        | Bounded memory/legacy overflow behavior; transport acknowledgments do not establish durable receipt.                                         | Direct processors or relay processors when gaps are acceptable.                                   |
| Raw packets, `reliable`, scope `receiver` | Hunter retains unconfirmed immutable batches; a terminal receiver commits payload and receipt/deduplication state before signing acceptance. | Direct terminal processors. A receiver with an external upstream rejects this scope.              |
| Raw packets, `reliable`, scope `central`  | The source retains packets until the pinned logical destination signs committed coverage, including through a replacement relay.             | Relay processors sharing one central receiver. Transit relays do not claim local durable custody. |
| Normalized events                         | Existing event spool, producer-session, and ingress-profile contracts. Raw packet options do not change these contracts.                     | Event-capable destinations with compatible negotiated profiles.                                   |

Reliable raw capture requires packet mode without event fallback and verified
mutual TLS. Explicit reliable settings fail when a peer cannot honor the contract;
they never silently downgrade to best effort or event mode. The default remains
best effort. `--packet-ack-scope` defaults to receiver only inside the reliable
profile; setting receipt or spool options with best effort is an error.

## Ordered endpoint selection

```bash
sudo lc hunt -i eth0 --processors relay-a:55555,relay-b:55555 \
  --tls-ca ca.pem --tls-cert edge-a.pem --tls-key edge-a.key
```

The same selectors apply to every hunter protocol subcommand. Tap and processor
external upstreams use `--processors` too; an absent upstream keeps tap standalone.
Tap capture, processing, PCAP writing and local subscribers remain in process
during an upstream outage.

```yaml
hunter:
  processors:
    - address: 192.0.2.10:55555
      tls_server_name: relay-a.example.com
    - relay-b.example.com:55555
  failover:
    attempt_timeout: 10s
    reconnect_attempts: 1
    retry_initial: 1s
    retry_max: 60s
```

Use `tap.processors`/`tap.failover` or `processor.processors`/`processor.failover`
for those roles. The timeout bounds setup, including dial, TLS, registration and
required stream readiness. Startup tries candidates in order. On disconnection,
the active endpoint gets the configured number of bounded reconnect attempts;
zero advances immediately. Failed endpoints have independent capped exponential
backoff with jitter. A working backup stays active: there is no automatic failback.
These defaults describe behavior, not a guaranteed contact or recovery time.

An explicit CLI selector replaces configured selectors, including the other
selector's YAML form. Scalar and list selectors at the same priority conflict.
Lists must be nonempty, with valid unique `host:port` addresses. Endpoint objects
accept `address` and optional `tls_server_name`; TLS credentials remain common to
the role, and an override requires TLS. Existing `--processor`/`-P` and scalar
`processor_addr` configuration remain valid. Tap/process retain their deprecated
`--upstream` and `upstream_addr` aliases individually. Self-traffic exclusions
follow the configured transport endpoints and are refreshed for connection attempts.

## Relay processors

```text
edge hunter -> relay-a or relay-b -> common central processor
```

The hunter keeps its original source, producer-session, capture-epoch, packet
timestamps and interface metadata across routes. Relay identity is a separate
transport claim. The central processor can analyze both routes in the same place;
finite live reassembly, call tracking and finalization limits still apply to late
packets. A long outage does not resurrect finalized state or transfer state between
independent processors.

The central node explicitly delegates origins to authenticated relays:

```yaml
processor:
  relay_origins:
    relay-a: [edge-a, edge-b]
    relay-b: [edge-a, edge-b]
  tls:
    cert_file: /etc/lippycat/central.pem
    key_file: /etc/lippycat/central.key
    ca_file: /etc/lippycat/ca.pem
    client_auth: true
```

Each relay has the corresponding processor ID and a verified client certificate
whose identity matches that ID. Each hop authorizes its immediate peer and allowed
original sources. Registration/topology visibility alone does not grant delegation.
Overlapping routes can carry old-relay backlog and new traffic from the same source;
replacing the active route does not authorize a new source or invalidate legitimate
historical records by itself.

Raw relay v1 uses a dedicated stream with an authenticated open and readiness ACK.
It preserves direct-hunter admission checks. A v1 refusal never falls back to the
legacy stream. Older upstreams that advertise no relay capability retain the legacy
best-effort path with an explicit warning; their direct-hunter admission may reject
relayed origins. Upgrade the central receiver and every transit relay before relying
on multi-origin raw handover. Reliable raw transport additionally requires its v1
RPC and the configured signed receipt authority at every usable route.

## Shared filter policy

The default `filter_policy.mode: processor` accepts each selected processor's
policy. Different processors may intentionally have different filters. To require
one policy across relays, configure `mode: shared` with the same domain, authority
and pinned signing certificate on the authority, replicas and hunters.

```yaml
hunter:
  filter_policy:
    mode: shared
    owner: shared
    domain: capture
    authority: central-policy
    trusted_cert: /etc/lippycat/policy-authority.pem
    state_file: /var/lib/lippycat/hunter-policy/policy.state
    startup: wait
```

```yaml
processor:
  filter_policy:
    mode: shared
    owner: shared
    domain: capture
    authority: central-policy
    trusted_cert: /etc/lippycat/policy-authority.pem
    signing_key: /etc/lippycat/policy-authority.key
    state_file: /var/lib/lippycat/central-policy/policy.state
    startup: local
    sync_interval: 5s
    replicas:
      - address: relay-a:55555
      - address: relay-b:55555
```

Only the authority has `signing_key` and the explicit replica list. A replica uses
its own state path, the same trust/domain/authority and no signing key. Replication
reconciles cold backups even when no hunter is connected. Shared-policy RPCs require
mutual TLS. `PublishSnapshot` additionally requires a verified publisher certificate
whose key matches the pinned policy authority; when API-key authentication is enabled,
its normal administrative authorization also applies. An arbitrary transport-trusted
client cannot ask the processor to mint policy.

The management `FilterPolicyService` exposes `PublishSnapshot`, `GetSnapshot`,
`ApplySnapshot` and `SubscribeSnapshots`. Publication supplies the expected previous
revision and a complete filter list. Generic owned IDs already have the form
`shared/<domain>/<id>` and remain unchanged. Empty snapshots explicitly delete the
owned policy; local operator filters remain separate, and ordinary mutations cannot
write into the reserved namespace. Hunters preserve `target_hunters`, verify signatures
and persistent monotonic revisions, reject conflicting or older snapshots, and consume
signed full replacements rather than unsigned deltas. Effective BPF/application changes
use the existing capture and producer-session drain/rotation boundary.

`startup: wait` requires an installed verified snapshot before capture. `cached`
requires a verified stored snapshot and restores it; `local` explicitly permits local
policy while waiting for shared state. Ordinary shared capture has no interception lease.
Policy readiness is published only after installation. A desired policy committed to disk
but not installed blocks processing until reconciliation; restarting reloads the signed
watermark rather than replacing it with unsigned or empty state.

Generic shared snapshots default to signed plaintext in private `0600` state files.
Use `storage_protection: encrypted` and `storage_keys` for encrypted policy state.
The LI owner always requires that explicit encrypted profile. Provision encrypted
stores offline from the same configuration:

```bash
lc -c authority.yaml set policy-store --node processor
lc -c edge.yaml set policy-store --node hunter
```

For tap use `--node tap`. Initialization is separate from runtime open, never
clobbers existing evidence, and never recreates a missing identity, snapshot or
usage ledger. Changing domain, authority, signing pin, owner or bound state identity
requires an explicit migration; deleting files or resetting keys is not recovery.

## Reliable raw packet setup

Choose a stable source ID, logical destination and receipt signer. Every route used
by one spool must reach that configured destination and receipt authority. A common
central receiver supplies one acceptance/deduplication database across relay
handover. Independent receivers do not acquire shared analysis or deduplication state.

Provision the source and terminal receiver stores explicitly before runtime:

```bash
lc set packet-spool --dir /var/lib/lippycat/edge-packets \
  --source-id edge-a --destination-id central-capture \
  --ack-scope central --protection private --max-bytes 33554432 \
  --max-record-bytes 4194304 --max-records 4096 --max-loss-ranges 4096 \
  --max-age 24h --exhaustion-policy drop_oldest

lc set packet-custody --dir /var/lib/lippycat/central-custody \
  --destination-id central-capture --protection private --max-bytes 33554432 \
  --max-record-bytes 4194304 --max-records 4096 --max-sessions 256 \
  --max-loss-ranges 4096
```

`private` means protected filesystem permissions with plaintext payloads. Use
`--protection encrypted --key-id <id> --key-file <private-32-byte-file>` for AES
protection, and matching runtime key references. Encryption keys must be independently
provisioned across policy, raw spool, custody, administrative state and LI journals;
reusing material under another key ID does not make it independent.

```yaml
hunter:
  hunter_id: edge-a
  processors: [relay-a:55555, relay-b:55555]
  forward_mode: packets
  packets:
    delivery_profile: reliable
    ack_scope: central
    destination_id: central-capture
    trusted_cert: /etc/lippycat/central-receipt.pem
    spool:
      dir: /var/lib/lippycat/edge-packets
      protection: private
      max_bytes: 33554432
      max_record_bytes: 4194304
      max_read_bytes: 16777216
      max_records: 4096
      max_loss_ranges: 4096
      max_age: 24h
      exhaustion_policy: drop_oldest
  tls:
    ca_file: /etc/lippycat/ca.pem
    cert_file: /etc/lippycat/edge-a.pem
    key_file: /etc/lippycat/edge-a.key
```

```yaml
processor:
  packets:
    receiver:
      enabled: true
      authority: central-capture
      signing_cert: /etc/lippycat/central-receipt.pem
      signing_key: /etc/lippycat/central-receipt.key
      store:
        dir: /var/lib/lippycat/central-custody
        destination_id: central-capture
        protection: private
        max_bytes: 33554432
        max_record_bytes: 4194304
        max_records: 4096
        max_sessions: 256
        max_loss_ranges: 4096
```

The receiver also needs normal mutual-TLS configuration and, for relays, the explicit
`relay_origins` map. Tap uses `tap.packets.receiver`. The examples' byte/count limits
are tunable examples, not an outage or throughput promise. Keep provisioning and runtime
identity/protection settings consistent. For encrypted raw stores, `keys` has the form:

```yaml
keys:
  active:
    id: edge-packets
    file: /etc/lippycat/keys/edge-packets.key
  prior: []
```

Policy encryption uses the same key-reference shape under `storage_keys`.
`--packet-delivery-profile reliable` and `--packet-ack-scope central` can override the
hunter's YAML profile and scope. Other source store settings are YAML. Reliable raw
mode rejects the legacy destructive disk-overflow buffer rather than silently migrating
or deleting it.

## Acceptance, replay and resource limits

A signed receipt covers a bounded origin/session/destination sequence identity and
committed payload or authenticated loss coverage. The source verifies the pinned
signer and scope before retiring records. Send completion and local transit ACKs do
not retire central-scope origin records. Relays can forward return receipts through
the current path; a receiver's committed data is not tied to the old route.

Receivers deduplicate before duplicate-sensitive analysis. Accepted but unfinished
payloads are recovered after a crash. Processing and arbitrary output side effects
remain at least once across a crash between output and the processing checkpoint:
there is no exactly-once PCAP, hook, log or MDF-output promise. Transport acceptance
is also separate from successful analysis or downstream delivery.

Capture can continue offline while policy permits and configured retention has room.
The spool enforces byte, age, per-record, record-count, retrieval and exact loss-range
bounds. `drop_oldest` and `drop_new` report durable bounded loss coverage. Unlimited
age or byte settings do not remove finite record/history bounds. Deduplication history
and retired-session tombstones are finite; exhaustion fails closed instead of reusing
an old identity. Plan explicit destination/session/store migration before those limits
are exhausted. Never delete history, a usage ledger or initialized identity to reset it.
Live encryption/signing-key resets are unsupported.

Original timestamps are retained. Delayed data still passes through bounded live
analysis; late packets, expired calls and finalized connections are not automatically
reopened. Finite storage cannot cover an unlimited blackout. Independent processors,
central failure, relay connectivity and MDF availability have separate failure models.
TLS session-key recovery across handover is unsupported; reliable raw mode rejects HTTP keylog configuration. Ordinary raw TLS payload forwarding remains supported.

## Optional LI handover

LI administration/delivery remains on LI-enabled central processor or tap builds.
A generic hunter can carry signed LI capture policy without the `li` build tag.
Use `filter_policy.owner: li`, retain the original `li-` filter IDs, and provision
encrypted policy and raw stores. The current hunter guard supports reliable encrypted
raw packet mode with synchronous filtering; VoIP call-buffer mode is explicitly rejected.
Ordinary best-effort or shared-owner capture does not require an ADMF, MDF or LI lease.

The central deployment additionally configures the following root-level settings:

```yaml
li:
  handover:
    enabled: true
    lease_duration: 2m
    allow_offline: false
    clock_uncertainty: 1s
    source_ids: [edge-a, edge-b]
```

These are deployment choices, not universal timing requirements. Signed
grants bind the authority incarnation, task activation/filter revision, source and
validity. Offline capture is disabled by default. If explicitly allowed, the generic
source enforces its bounded signed lease, clock uncertainty/rollback and restart rules;
contact loss or reboot cannot renew authority. A disconnected source cannot receive an
immediate revocation. Task `ImplicitDeactivationAllowed` and existing central admission,
revocation, finalized-call and X3-age checks remain authoritative. Earlier capture does
not grant historical delivery after task expiry, and a central receipt is not MDF delivery.

## Operate and recover

Monitor the selection candidate/active/attempt fields and failover reason separately
from upstream route identity, policy readiness, queue depth and signed receipt progress.
Raw status reports the delivery profile, scope, destination/session, queued records/bytes,
oldest age, receipt sequence, replay/duplicate/drop/late observations and policy revision.
The origin drop count records durably lost batches across restart, including confirmed
gaps; replay, duplicate, and late observations count packets in the current runtime.
A configured upstream with no active generation is not a healthy empty route. SLOW/PAUSE
flow control represents pressure and does not by itself authorize switching every hunter
to another route to the same overloaded central receiver.

Recover initialized stores with the original identity, destination, policy pin and keys.
Preserve crash/partial-initialization evidence and legacy overflow files during migration.
A missing ledger, corrupt ciphertext, signature mismatch or policy-installation fault
must be reconciled explicitly; runtime startup must not initialize a replacement. Validate
a complete route and compatible peers before relying on its profile. Upgrade receivers
before relays and sources, and test the deployment's actual loss/contact pattern without
assuming an outage duration or automatic state-replication guarantee.
