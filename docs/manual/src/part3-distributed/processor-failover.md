# Failover and Reliable Delivery {#failover-and-reliable-delivery}

Ordered processor lists let edge hunters switch between available processors, including relay processors forwarding to a common central processor. LI is optional. A common upstream can keep analysis in one place; independent processors keep separate analysis state and output files.

## Select Routes {#select-routes}

Use `--processors` instead of `--processor` for ordered alternatives. One connection is active. Each setup attempt is bounded by `--processor-attempt-timeout` (default `10s`); `--processor-reconnect-attempts` defaults to `1`, and `0` advances immediately. Failed endpoints have independent capped backoff with jitter. A working backup stays active without automatic failback.

<!-- i18n:skip -->

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

An explicit CLI selector replaces configured scalar or list selectors. Conflicting selectors at the same priority are rejected. Endpoint objects accept only `address` and optional `tls_server_name`; credentials remain in the role's TLS configuration. Tap and processor use `tap.processors` and `processor.processors` for external upstreams. Tap capture and local outputs continue during an upstream outage.

## Authenticate Relay Origins {#authenticate-relay-origins}

Relay processors forward to a common central processor. Mutual TLS authenticates each immediate peer; `relay_origins` explicitly delegates the original hunters that each relay may carry. Registration or topology visibility alone grants no delegation. Original source/session, capture epoch, timestamps and interface metadata remain separate from relay identity.

<!-- i18n:skip -->

```yaml
processor:
  relay_origins:
    relay-a: [edge-a, edge-b]
    relay-b: [edge-a, edge-b]
```

Raw relay v1 requires an authenticated open and readiness ACK. A refusal never falls back to legacy admission. Older upstreams retain the warned legacy best-effort path, which may reject relayed origins. Upgrade receivers and relays before sources rely on multi-origin handover or reliable raw v1 receipts.

## Share Signed Filter Policy {#share-signed-filter-policy}

The default `filter_policy.mode: processor` accepts each selected processor's policy. Optional `mode: shared` pins a domain, authority and signing certificate. Full signed snapshots preserve `shared/<domain>/<id>` identifiers and hunter targeting. Monotonic persisted revisions reject stale or conflicting restoration; an empty snapshot deletes the owned policy. Local operator filters remain separate and cannot overwrite the protected namespace.

The authority publishes complete snapshots through `FilterPolicyService.PublishSnapshot` and configures all candidate `replicas`, including cold backups with no connected hunter. Shared-policy RPCs require mutual TLS; publication additionally requires the pinned authority's verified client key and applicable administrative authorization. An arbitrary transport-trusted client cannot mint policy. Signing keys stay on the authority.

<!-- i18n:skip -->

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

`startup: wait` requires an installed signed snapshot before capture. `cached` requires a verified stored snapshot; `local` explicitly permits local policy while waiting. Ordinary shared policy has no interception lease. BPF/application changes cross the existing capture and producer-session drain boundary. Committed policy that cannot be installed blocks processing until reconciliation; restart preserves the signed rollback watermark.

Generic policy state defaults to signed plaintext with private permissions. Encrypted state uses `storage_protection: encrypted` and `storage_keys` with `active` and optional `prior` key references. The LI owner requires encryption. Provision encrypted state offline from the same node configuration; runtime never recreates missing identity, snapshot or usage-ledger files.

<!-- i18n:skip -->

```bash
lc -c authority.yaml set policy-store --node processor
lc -c edge.yaml set policy-store --node hunter
```

## Retain Reliable Raw Packets {#retain-reliable-raw-packets}

Raw packets default to best effort. Enable `--packet-delivery-profile reliable` for recoverable immutable batches; this requires packet mode without event fallback and verified mutual TLS. Receipt/spool options are rejected with best effort, and incompatible peers never cause a silent downgrade. Existing normalized-event spool contracts remain separate.

`--packet-ack-scope` defaults to `receiver` inside the reliable profile. Receiver custody currently requires a terminal receiver; a processor with an external upstream rejects it. Use `central` scope for relay processors feeding one central receiver. The source pins the logical destination and receipt-signing certificate and retains records until that destination signs committed coverage; transit acknowledgments cannot retire central-scope records.

<!-- i18n:skip -->

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
```

The terminal receiver configures `processor.packets.receiver` or `tap.packets.receiver`: enable custody, set matching `authority` and store `destination_id`, receipt `signing_cert`/`signing_key`, and explicit store protection and byte/record/session/loss-range bounds. It also needs normal mutual-TLS configuration and any relay delegation. All routes used by one source spool must reach its configured logical destination and trusted receipt authority.

Provision source and custody stores offline with matching identities and protection. The example limits are configurable bounds, not a contact-duration or throughput guarantee.

<!-- i18n:skip -->

```bash
lc set packet-spool --dir /var/lib/lippycat/edge-packets \
  --source-id edge-a --destination-id central-capture \
  --ack-scope central --protection private --max-bytes 33554432
lc set packet-custody --dir /var/lib/lippycat/central-custody \
  --destination-id central-capture --protection private --max-bytes 33554432
```

`private` stores plaintext with protected permissions. `encrypted` uses independently provisioned AES keys and explicit `--key-id`/`--key-file` initialization references. Runtime raw stores use `keys`; policy state uses `storage_keys`. Their shape is `active: {id, file}` with optional `prior` references. Policy, raw spool, custody, administrative state and LI journals require independent encryption material. The legacy destructive overflow buffer is not silently migrated or deleted.

Receivers commit payload, deduplication state and signed receipt coverage before acceptance. Duplicate ingress is suppressed before analysis, and accepted unfinished work is recovered after restart. A crash between an output side effect and its processing checkpoint can repeat that output: transport receipts do not promise exactly-once PCAP, hooks, logs or MDF delivery.

Offline capture continues only while policy permits and retention has capacity. Byte, age, per-record, retrieval, record-count and exact loss-range limits remain enforced; `drop_oldest` and `drop_new` retain bounded durable loss coverage. Deduplication history and retired-session tombstones are finite and fail closed at capacity. Preserve original identities and evidence; migrate explicitly rather than deleting history or resetting keys.

## Apply Optional LI Authority {#apply-optional-li-authority}

LI-enabled central processors manage ADMF/MDF integration. Generic hunters can carry signed `owner: li` policy without an LI build, preserving original `li-` IDs. This profile requires verified mTLS, encrypted policy and raw stores, reliable raw packet delivery and a current signed finite capture policy. VoIP capture supports `signalling_policy: matched` or `none`; `all` is rejected because unselected signalling exceeds the capture grant. Processor media rules alone do not grant capture authority. Ordinary capture does not need an ADMF, MDF or interception lease.

Root-level `li.handover` configures `enabled`, positive `lease_duration`, `allow_offline` (default false), bounded `clock_uncertainty` and explicit `source_ids`. Signed grants bind authority incarnation, activation/filter revisions, source and validity. Offline capture, when explicitly allowed, remains bounded by the signed lease; contact loss, clock rollback or reboot cannot renew it. A disconnected source cannot receive immediate revocation.

Task `ImplicitDeactivationAllowed`, central activity/revocation checks, finalized-call boundaries and X3 admission-age limits remain authoritative. Earlier capture does not authorize delivery after task expiry, and central durable receipt is separate from MDF delivery.

## Observe and Recover {#observe-and-recover}

Monitor configured candidates, active/attempt endpoints and reasons separately from upstream identity, policy readiness, queue depth and receipt progress. Raw status includes profile, scope, destination/session, queued records/bytes, oldest age, acknowledged sequence, replay/duplicate/drop/late observations and policy revision. An absent upstream generation is not a healthy empty route; SLOW/PAUSE pressure alone is not route failure.

Restore initialized stores with their original destination, signing pin and encryption keys. Missing ledgers, corrupt ciphertext, signature mismatch or failed policy installation require explicit reconciliation. Live key resets and automatic store reinitialization are unsupported. Original timestamps survive replay, but bounded live analysis does not automatically reopen finalized calls/connections; finite storage cannot cover unlimited outages. TLS session-key recovery across handover is unsupported; reliable raw mode rejects HTTP keylog configuration. Ordinary raw TLS payload forwarding remains supported.
