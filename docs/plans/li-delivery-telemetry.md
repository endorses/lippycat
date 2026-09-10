# LI delivery telemetry

Expose delivery observations through `lc show status` for processor and tap.
Keep encoding distinct from successful local writes and receiver acceptance.
Queued counters retain enqueue-call units; written and dropped counters count
destination copies. Diagnostics include queue age, terminal drop reasons,
connection state and separate X2/X3 keepalive observations.

- [x] Add additive management protocol fields and regenerate bindings.
- [x] Snapshot delivery and per-interface connection health safely.
- [x] Populate processor status and CLI JSON, including disabled-build behavior.
- [x] Verify overflow, unavailable peers, stalled writes and missing keepalive ACKs.
- [x] Document counter semantics and diagnostic limitations.
- [x] Format, run relevant tests and review changes.

Validation passed: focused delivery race tests cover unavailable destinations,
stalled TLS writes, missing ACKs and live snapshots. Processor status tests cover
overflow, fan-out units, protobuf transport, destination removal and unavailable
telemetry; they pass with `all li`, `processor li` and `tap li` (race checks on
`all li` and `tap li`). Non-LI `all` status tests and the statusclient package
tests also pass. Commit the implementation and this completed plan together.
