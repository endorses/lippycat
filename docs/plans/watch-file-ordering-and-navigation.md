# Offline capture ordering and navigation corrections

Date: 2026-09-05

Real capture testing exposed incomplete viewport loads after page and end jumps,
and the strict timestamp policy prevented valid captures with small backward
steps from opening. The capture footer must also keep its reserved toast space.

- [x] Load visible rows above and below selection after page and top/bottom jumps;
      preserve bounded-cache fallback and obsolete-request cancellation.
- [x] Restore blank toast space; show dataset resource information in Statistics.
- [x] Order normalized offline packets using bounded disk storage before analysis,
      preserving timestamps, source identity and deterministic ties. Account for
      sorting files under the shared session disk budget and clean up on failure.
- [x] Integrate cancellable ordering progress into the model-owned open workflow;
      update operator documentation and the previous strict-ordering contract.
- [x] Verify synthetic regressions, both build tags, concurrency, and the user's
      original capture. Independently review changes, format and commit.

The strict streaming reader remains available for existing non-dataset callers.
Offline watch datasets accept arbitrary timestamp order without silently changing
timestamps, dropping packets or allocating packet-count-sized arrays in RAM.

Verification completed:

- Full capture/offline/TUI/watch suites passed uncached under `all` and `tui`.
  Full offline/TUI race suites and focused capture sorting race checks passed.
- Hunter, processor, tap, CLI, all and TUI binaries built successfully.
- Independent reviews checked the viewport regression, exact ordering/metadata,
  bounded scratch ownership, cancellation and cleanup retry, and Statistics.
- The original private `gtest6.pcap` indexed directly into 316,382 logical packets,
  matching the previously ordered copy; first/last details loaded successfully.
  No private capture data was added to the repository.
- Fresh-process one-source indexer runs at 100,000 and 1,000,000 packets used
  93,580 and 95,820 KiB peak RSS (+2.19 MiB), with 9,986,080 and 10,052,416 bytes
  live heap. Throughput was 46,096 and 46,146 packets/s; cooperative cancellation
  and cleanup took 0.816 and 1.902 ms. Each retained 10,000 events. Root checked
  the raw benchmark logs and confirmed the previous scaling/cancellation gates.

These are fixed-flow, warm-filesystem reference runs, not universal RSS or latency
limits. Sorting adds a read/spool and merge pass before analysis, including for
already chronological files. Temporary raw bytes plus two 64-byte-per-packet key
streams share the configured disk budget; the obsolete key stream is removed
before replay and all sorting files are removed before Ready. The previous phase
6 throughput measurements describe the earlier strict streaming path.
