# SIP priority buffer capacity and telemetry

**Status:** Complete

## Objective

Make the SIP priority lane deliberately sized and fully observable across local,
hunter, and tap capture paths. Preserve non-blocking live capture behavior while
distinguishing priority degradation from packet loss and exposing enough queue
state to diagnose bounded burst pressure.

All examples, fixtures, and documentation produced by this work must use
synthetic traffic, identifiers, addresses, and measurements.

## Design contract

- [x] Replace the fixed SIP lane capacity with a resolved runtime setting.
- [x] Define `sip_buffer_size = 0` as automatic sizing, with the SIP input lane
      resolved to the regular input lane capacity.
- [x] Treat a positive SIP buffer size as an explicit override and reject
      negative values during command/configuration validation.
- [x] Retain `NewPacketBuffer(ctx, size)` as a compatibility wrapper using the
      automatic policy, and add a configuration-based constructor for callers
      that own an explicit SIP capacity.
- [x] Define a SIP demotion as a classified SIP packet rejected by the full SIP
      lane but successfully admitted to the regular lane.
- [x] Keep demotions separate from drops: aggregate drop totals must continue to
      include regular-lane drops, final SIP drops, and downstream batch drops,
      but never SIP demotions.
- [x] Treat all counters as cumulative and monotonic for one buffer lifetime;
      treat lane lengths as instantaneous approximate gauges and capacities as
      immutable for that lifetime.
- [x] Describe the merger as preferential service rather than strict global
      packet ordering.
- [x] Preserve `SendBlocking` semantics: it waits for SIP-lane capacity and does
      not demote or drop a packet because a lane is temporarily full.
- [x] State explicitly that larger queues absorb bounded bursts but cannot make
      a sustained arrival rate above downstream service capacity lossless.

## Phase 1: Core packet-buffer API and accounting

- [x] Add a packet-buffer configuration type and one resolver responsible for
      validating and resolving regular, SIP, and merged-output capacities.
- [x] Store the resolved capacities on `PacketBuffer` and remove comments that
      assume SIP volume or overflow frequency.
- [x] Replace the compile-time SIP channel capacity at construction with the
      resolved capacity.
- [x] Add an atomic cumulative SIP demotion counter and a public accessor.
- [x] Increment the demotion counter only after successful fallback admission to
      the regular lane; do not increment it when both lanes reject the packet.
- [x] Preserve the existing regular-drop, SIP-drop, and classified-SIP counter
      meanings.
- [x] Add a single packet-buffer snapshot API containing regular, SIP, and
      output lane lengths and capacities plus classified, demoted, and dropped
      counters.
- [x] Retain existing length, capacity, and counter accessors for compatibility,
      implementing them from the same state where practical.
- [x] Log the resolved regular, SIP, output, and aggregate capacities once when
      a production-owned buffer is created.
- [x] Ensure capture restart/reconfiguration paths recreate buffers with the
      same resolved policy and explicit override.

Primary files:

- `internal/pkg/capture/capture.go`
- `internal/pkg/capture/telemetry.go`
- `internal/pkg/hunter/capture/manager.go`
- `internal/pkg/processor/source/local.go`

## Phase 2: Configuration and command surfaces

- [x] Add `--sip-buffer-size` to hunt and tap command families with a default of
      `0` for automatic sizing.
- [x] Bind the flags to `hunter.sip_buffer_size` and `tap.sip_buffer_size`, and
      preserve normal flag-over-config precedence.
- [x] Add the resolved setting to hunter, capture-manager, and local-source
      configuration types and thread it to every production buffer constructor.
- [x] Add `sip_buffer_size` as the equivalent generic capture configuration key
      for direct local capture paths that construct their own packet buffer.
- [x] Validate negative values before capture starts and return an actionable
      error containing the invalid setting name.
- [x] Cover default, explicit override, configuration-file, environment, and
      CLI precedence in command/configuration contract tests.
- [x] Verify that hunter restarts and local-source filter restarts retain the
      configured SIP capacity.

Primary files:

- `cmd/hunt/hunt.go`
- `cmd/hunt/config.go`
- `cmd/hunt/cli_contract_test.go`
- `cmd/hunt/config_test.go`
- `cmd/tap/tap.go`
- `cmd/tap/runtime.go`
- `cmd/tap/runtime_test.go`
- `internal/pkg/hunter/hunter.go`
- `internal/pkg/hunter/capture/manager.go`
- `internal/pkg/processor/source/local.go`
- `internal/pkg/capture/config_test.go`

## Phase 3: Local telemetry and overload summaries

- [x] Extend typed capture telemetry with SIP demotions and regular, SIP, and
      output lane length/capacity fields.
- [x] Preserve `buffer_len` as a compatibility aggregate while adding explicit
      per-lane length and capacity fields to capture heartbeats.
- [x] Emit the cumulative SIP demotion counter on capture heartbeats.
- [x] Ensure shared-buffer counters and gauges are sampled once rather than
      summed once per interface.
- [x] Replace every-N-packet overflow warnings with a per-buffer, time-gated
      summary that reports interval deltas, cumulative totals, and lane
      occupancy/capacity.
- [x] Cover regular drops, SIP demotions, and final SIP drops in the summary
      without rate-limiting their underlying counters.
- [x] Emit a final bounded summary during orderly shutdown when unreported
      demotions or drops remain.
- [x] Make warning throttling deterministic in tests through an injectable clock
      or a small independently testable rate gate.

Primary files:

- `internal/pkg/capture/capture.go`
- `internal/pkg/capture/telemetry.go`
- `internal/pkg/capture/telemetry_test.go`
- focused packet-buffer logging tests under `internal/pkg/capture/`

## Phase 4: Distributed telemetry and operator visibility

- [x] Add backward-compatible protobuf fields for SIP demotions and per-lane
      queue lengths/capacities to packet-batch and hunter-status telemetry.
- [x] Regenerate checked-in Go protobuf bindings with the repository-supported
      generation workflow.
- [x] Thread the new fields through pipeline contracts, gRPC adapters, hunter
      batching and heartbeats, processor source statistics, hunter state, and
      processor status responses.
- [x] Propagate the fields through shared display types, remote-capture
      conversion, status-client JSON, and TUI statistics models.
- [x] Present SIP demotions as priority degradation/pressure, not packet loss.
- [x] Preserve existing aggregate dropped-packet formulas and add invariant
      tests proving demotions do not affect them.
- [x] Add protobuf round-trip and old-peer compatibility tests so absent new
      fields decode safely as zero.
- [x] Add end-to-end synthetic telemetry tests covering hunter-to-processor and
      tap/local-source paths.

Primary files:

- `api/proto/data.proto`
- `api/proto/management.proto`
- `api/gen/data/`
- `api/gen/management/`
- `internal/pkg/pipeline/contracts.go`
- `internal/pkg/pipeline/grpcadapter/`
- `internal/pkg/hunter/forwarding/manager.go`
- `internal/pkg/hunter/connection/manager.go`
- `internal/pkg/processor/source/`
- `internal/pkg/processor/hunter/manager.go`
- `internal/pkg/processor/processor_grpc_handlers.go`
- `internal/pkg/types/packet.go`
- `internal/pkg/remotecapture/client_conversion.go`
- `internal/pkg/statusclient/json.go`
- `internal/pkg/tui/capture_events.go`
- `internal/pkg/tui/components/statistics.go`

## Phase 5: Deterministic verification

- [x] Add focused tests with explicit tiny capacities and controlled channel
      draining instead of timing-dependent high-volume traffic.
- [x] Verify automatic capacity resolution and explicit overrides.
- [x] Verify that SIP packets enter the priority lane while it has capacity.
- [x] Verify that a full SIP lane plus available regular capacity produces one
      demotion, no SIP drop, and successful admission.
- [x] Verify that both input lanes being full produces one final SIP drop and no
      demotion for that packet.
- [x] Verify that regular-packet drops remain independently accounted.
- [x] Verify snapshot lengths/capacities and the invariant that aggregate
      occupancy never exceeds the sum of resolved channel capacities.
- [x] Verify preferential dequeue behavior without asserting strict global
      ordering that the concurrent merger does not guarantee.
- [x] Verify `SendBlocking` waits for SIP capacity and never increments demotion
      or drop counters.
- [x] Verify close, drain, concurrent send, and restart behavior with the race
      detector.
- [x] Verify warning summaries emit initially, remain suppressed inside the
      interval, and later report correct interval and cumulative values.
- [x] Use only synthetic SIP messages, network addresses, identifiers, traffic
      rates, and capacity values in tests and examples.

Suggested focused test locations:

- `internal/pkg/capture/packet_buffer_priority_test.go`
- `internal/pkg/capture/telemetry_test.go`
- `internal/pkg/hunter/forwarding/manager_test.go`
- `internal/pkg/hunter/connection/manager_test.go`
- `internal/pkg/processor/source/local_test.go`
- existing protobuf, status-client, remote-capture, and TUI round-trip tests

## Phase 6: Documentation

- [x] Document `--sip-buffer-size`, its automatic mode, explicit override, and
      memory/headroom tradeoff for hunt and tap.
- [x] Document the generic direct-capture configuration key and its precedence.
- [x] Explain the difference between classified, demoted, and dropped SIP
      counters and how to interpret each per-lane gauge.
- [x] Explain that queue capacity mitigates bounded bursts while sustained
      overload requires downstream throughput, filtering, or workload changes.
- [x] Add an overload troubleshooting sequence using per-lane occupancy,
      demotions, final drops, downstream queue pressure, and kernel drops.
- [x] Keep examples synthetic and avoid deployment-derived values or identifiers.

Documentation targets:

- `cmd/hunt/README.md`
- `cmd/tap/README.md`
- `docs/manual/src/part3-distributed/hunt.md`
- `docs/manual/src/part3-distributed/tap.md`
- `docs/manual/src/appendices/command-reference.md`
- `docs/manual/src/appendices/config-reference.md`
- relevant performance and troubleshooting documentation

## Validation and closure

- [x] Format every changed Go file with `gofmt` before staging.
- [x] Run the repository protobuf generation/check workflow and confirm generated
      files have no unexplained drift.
- [x] Run targeted tests for capture, hunter capture/forwarding/connection,
      processor source/status, remote capture, status client, and TUI telemetry.
- [x] Run `go test -race` for the capture package and other concurrency-sensitive
      packages changed by the implementation.
- [x] Build and test the `all`, `hunter`, and `tap` tag combinations.
- [x] Run `make vet` and `make test`, resolving only issues caused by this work;
      stop and report unrelated blockers according to repository policy.
- [x] Audit the completed implementation against every plan item and check off
      only tasks supported by code, tests, or documentation.
- [x] Commit code, generated artifacts, documentation, and this completed plan
      together.

## Acceptance criteria

- [x] No production capture path constructs a packet buffer with an
      unconfigurable fixed SIP capacity.
- [x] Operators can select automatic sizing or an explicit SIP capacity through
      supported command/configuration surfaces.
- [x] Every successfully demoted SIP packet is counted exactly once and no
      demotion is included in packet-loss totals.
- [x] Local and remote telemetry expose enough per-lane state to attribute
      priority degradation and saturation.
- [x] Overflow logging remains useful under heavy pressure without producing a
      warning per fixed number of packets.
- [x] Existing peers remain wire-compatible, and existing consumers retain the
      previous aggregate fields.
- [x] Tests demonstrate bounded-burst behavior and accounting invariants without
      claiming that finite buffering solves sustained overload.
