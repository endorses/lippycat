# Compact completed-index performance

Scope: address Phase 3's measured serialization, allocation and storage gaps
without changing completed-only readiness or selecting the production backend.
Preserve preexisting working-tree changes and the legacy comparison oracle.

- [x] Record a current baseline and capture identity using fresh benchmark processes.
- [x] Remove repeated schema reflection and row decode/re-encode work from block construction.
- [x] Reduce completed block storage with bounded encoding while preserving checksums and direct lookup.
- [x] Verify semantic parity, malformed-input handling, budgets, ownership and race checks.
- [x] Measure three fresh runs per backend, document gains and remaining bottlenecks.
- [x] Format and commit only these changes and the verified plan/results.

Verification and measurements:
[performance follow-up](../research/watch-file-compact-performance.md).
The 100 MB storage target and sampled 10% legacy regression tolerances are met;
the three-second readiness target and the remaining Phase 4 gates remain open.
