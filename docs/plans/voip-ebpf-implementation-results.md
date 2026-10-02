# VoIP eBPF implementation evidence

Date: 2026-10-02. Status: **verified**. This records evidence for the
[implementation plan](voip-ebpf-media-admission.md). The source rationale is the
[research report](../research/voip-ebpf-media-admission.md).

## Environment and reproducibility

The privileged tests ran in a disposable Docker network namespace on Linux
`6.18.54-1-lts`, amd64, using Go `1.27.1-X:nodwarf5`. The checked-in toolchain
Dockerfile selects Ubuntu 24.04 by image digest and installs clang 18, libbpf
headers and libpcap development libraries. Kernel capabilities were exercised
by actual program loading, `BPF_PROG_TEST_RUN`, socket attachment and veth traffic;
no production deployment was performed. Other kernels, CPU architectures,
macOS/Windows and CUDA are not covered by this run.

```sh
make test-ebpf
LIPPYCAT_EBPF_MEASURE=1 make test-ebpf
```

The second invocation adds the exploratory workload. It retains all ordinary
integration tests; measurements do not turn a failing correctness run into a
pass. Its `EBPF_MEASUREMENT` JSON lines contain raw counters for each scenario.

## Verification

- Real kernel policy, expanded libpcap predicate equivalence, compatibility,
  explicit restrictions, and live socket recreation/snapshot-length tests passed.
  Fixtures cover Ethernet/VLAN byte views, IPv4/IPv6, fragments, truncation and
  encapsulation. This does not claim hardware VLAN ancillary metadata coverage;
  unsupported VLAN predicates and cooked links are rejected at startup.
- Both hunter and tap command enforcement/shadow tests passed. Selected media
  outside the old default RTP range reaches per-call output; unrelated media and
  an explicit excluded port do not. Remote hunter heartbeat status preservation
  passes focused race tests and these command tests.
- Both command topologies passed shared-interface and isolated-domain tests.
  Equal Call-IDs/endpoints in an unselected domain do not inherit selection.
  TAP UDP/TCP domain routing and local-source direct/inherited provenance tests
  passed with `go test -race -tags all,li`.
- Both topologies passed open/closed endpoint-capacity recovery and live exact-IP,
  CIDR update and no-filter tests, with explicit restrictions still enforced.
  The hunter BufferManager bug is fixed: matched media uses authoritative endpoint
  resolution and the captured call lifetime after temporary packet buffers expire.
  Regression tests cover expiry, ambiguity, endpoint removal, Call-ID reuse and
  inherited filter identity, without extending packet retention.
- Full `internal/pkg/voip` race tests passed with `all,li`. Focused registry,
  controller, bridge, configuration, lifetime diagnostics, capture telemetry and
  scoped processor race suites passed. Pending owner-capacity recovery retains
  bounded stable tokens and retries current registry endpoints; real hunter/tap
  command tests verify recovery without another SIP message and reject unrelated
  and retired endpoints.
- `make test`, `make vet` and `make build-matrix` passed on the final implementation.
  The matrix builds six roles and supported LI combinations. CUDA was explicitly
  skipped because this is not a configured CUDA builder.
- `LIPPYCAT_EBPF_MEASURE=1 make test-ebpf` passed the complete real kernel,
  libpcap, command, domain, selector, endpoint/owner recovery and workload suites.
- The actual kernel shadow-correlation test passed: deterministic packet identities,
  CLOCK_MONOTONIC selection/publication boundaries and captured generations classify
  historical decisions. Duplicate ambiguity and bounded ring loss are tested.
- The bounded closure review found and fixed two defects: hunter domain routing
  duplicated configured process budgets, and global registry revision drift could
  suppress another call's endpoint publication. Deterministic aggregate-budget
  and unrelated-call interleaving regressions passed under the race detector.
  The single integrated post-fix review found no further issues.
- The gopacket patch reconstructs all three changed binding files byte-for-byte
  from v1.1.19. Focused binding tests and manager restart/readiness regression pass.
  Offline rejection, disabled resource checks, actual unsupported-platform stub
  source tests and Darwin backend cross-compilation passed. Native non-Linux
  libpcap capture remains unexercised.
- Regeneration in the recorded toolchain reproduced both checked-in objects and
  generated Go files byte-for-byte. Object SHA-256 values are
  `b94be78af05b6493d78416cd1d6679daf203adcf551cd4a547dd517eabba3bf6`
  (little endian) and
  `fa7998d30aa09390b39c2ea2858a1b985fc7287d027ccda303139127eaeb7afb`
  (big endian). Big-endian runtime execution remains unexercised.

## Exploratory 100-calls/s workload

Each scenario creates 200 logical calls at a scheduled 100 calls/s. A leg is a
separate SIP Call-ID with its own SDP endpoint pair. The first scenario matches
10% of calls, with one leg and a one-second lifetime; the second matches 50%,
with two legs and a two-second lifetime. Every leg offers media at 50 packets/s,
including an immediate packet directly after its INVITE. Ports are inside the
legacy default range so broad and selective modes see equivalent offered traffic.
A separate selected SDP probe precedes the workload.

All six cases completed on the final implementation after the closure fixes. These are short observations on this machine, **not
acceptance thresholds or a production capacity claim**. The broad mode uses the
existing disabled path, including its buffered capture behavior; enabled modes
request immediate capture. Differences in initial media output therefore include
userspace scheduling and buffering as well as the admission window.

| Match / legs / lifetime | Mode    | Captured packets | Output media | Immediate selected media output / sent | Allocated MiB | Allocations | Process CPU seconds | Peak RSS MiB |
| ----------------------- | ------- | ---------------: | -----------: | -------------------------------------: | ------------: | ----------: | ------------------: | -----------: |
| 10% / 1 / 1s            | broad   |            10392 |          922 |                                 4 / 20 |         39.15 |      457572 |               0.292 |       149.71 |
| 10% / 1 / 1s            | shadow  |            10401 |          983 |                                 3 / 20 |         43.91 |      519606 |               0.365 |       162.56 |
| 10% / 1 / 1s            | enforce |             1381 |          980 |                                 0 / 20 |         18.51 |      226024 |               0.261 |       138.87 |
| 50% / 2 / 2s            | broad   |            40777 |        19318 |                               14 / 200 |        300.63 |     3305490 |               1.005 |       161.99 |
| 50% / 2 / 2s            | shadow  |            40801 |        19827 |                               27 / 200 |        316.84 |     3575450 |               1.153 |       178.60 |
| 50% / 2 / 2s            | enforce |            20601 |        19800 |                                0 / 200 |        261.78 |     2877049 |               1.018 |       174.40 |

Allocations are cumulative runtime `TotalAlloc`/`Mallocs` deltas from pprof heap
snapshots around the workload, including identical diagnostic sampling overhead.
CPU and peak RSS are OS process-accounting values and include startup/shutdown.
Captured/forwarded counters and queue occupancy are sampled from command status;
queue peaks are sampled at approximately 100ms, so transient peaks can be missed.
PCAP output is counted after graceful shutdown. Zero reported kernel/queue loss
is not evidence of zero initial or userspace-selection loss.

| Match / legs | Mode    | Offered media | Forwarded packets | Peak endpoint entries | Peak sampled queue packets | Update errors | SDP capture-to-publication upper bound (ms) |
| ------------ | ------- | ------------: | ----------------: | --------------------: | -------------------------: | ------------: | ------------------------------------------: |
| 10% / 1      | broad   |         10000 |               963 |                     0 |                          0 |             0 |                              not applicable |
| 10% / 1      | shadow  |         10000 |              1024 |                    42 |                          0 |             0 |                                       0.339 |
| 10% / 1      | enforce |         10000 |              1021 |                    42 |                          0 |             0 |                                       0.299 |
| 50% / 2      | broad   |         40000 |             19719 |                     0 |                          0 |             0 |                              not applicable |
| 50% / 2      | shadow  |         40000 |             20228 |                   402 |                          1 |             0 |                                       0.686 |
| 50% / 2      | enforce |         40000 |             20201 |                   402 |                          0 |             0 |                                       0.658 |

Actual offered call rates were approximately 99.94–99.98 calls/s. All scenarios
reported 0 capture-loss and 0 queue-loss counts in total. The plain UDP workload had
0 fragment/encapsulation/unknown compatibility passes; the kernel fixture
suite exercises those forms separately. Shadow collection changes load and does
not prove equivalent timing in enforcement.

The publication sample subtracts the probe's kernel capture timestamp (from its
written SIP PCAP) from the first observed confirmed publication wall time. It
includes SIP processing and endpoint installation; it is an upper bound because
periodic reconciliation can refresh the reported publication time before the
status query. This is one probe per enabled scenario, not a latency distribution
under sustained load. The immediate selected-media counts measure initial output
loss independently. Enforcement retained 0 of 220 immediate selected packets in this
run; early packet loss is consistent with the chosen capture-after-match semantics.

The observed reduction in userspace deliveries and allocations at low match rates
supports the mechanism's purpose. It does not justify an additional optimization
cycle or establish a throughput guarantee.

## Commands and qualification limits

```sh
make test
make vet
make build-matrix
LIPPYCAT_EBPF_MEASURE=1 make test-ebpf
go test -race -tags all,li ./internal/pkg/mediaadmission ./internal/pkg/voip/admission ./internal/pkg/voip ./internal/pkg/voip/processor ./internal/pkg/processor/source ./cmd/hunt ./cmd/tap
```

Affected capture readiness/restart, telemetry, registry and binding tests were
also run under the race detector as recorded in the plan. Native non-Linux capture,
big-endian runtime, other kernel/libpcap releases, CUDA and production rollout are
unexercised. Cooked links and VLAN ancillary predicates are explicitly rejected,
not untested supported promises. No performance threshold or production capacity
claim is inferred from these measurements. Raw values are in
[the measurement artifact](../research/voip-ebpf-measurements.json).
