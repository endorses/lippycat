# Repeated offline sniff replay

Add `--replay-loop N` (default 1, 0 means continuous) and
`--replay-loop-delay duration` (default 0) to file replay in `lc sniff` and its
protocol subcommands. Preserve each session's virtual interface and output sinks
across passes, reset replay timing and analysis state between passes, and make
startup, pacing, and inter-pass waits cancellable.

- [x] Add validated replay settings, ordered repeated file reads, finite/continuous execution, error propagation, and cancellation.
- [x] Keep output sinks and the virtual interface open once per session; reset timed injection and per-pass protocol state.
- [x] Integrate generic/RADIUS and DNS, HTTP, TLS, email, and VoIP sniff paths without changing default one-pass behavior.
- [x] Test counted replay, ordered multi-file output, output-file retention, analysis reset, continuous cancellation, empty filtered replay, and timed cancellation.
- [x] Document flags, configuration, and examples; translate affected manual content into German and Catalan.
- [x] Run focused Go checks, `make manual-check`, strict translation checks, and `make manual`; perform one bounded closure review.
- [x] Format and commit only this feature and its plan, preserving the prior uncommitted synthetic-demo work.

Continuous replay must stop on errors or when a pass produces no matching input
packets, rather than repeatedly rereading an empty capture. Delay applies only
between passes. Source capture timestamps and packet bytes remain unchanged; existing TCP SIP
output reconstruction is preserved. Injected
traffic receives the kernel's current timestamps. Repeated files are replayed as
observations, rather than establishing new authenticated network sessions.

The previously observed TUI shutdown issue is outside this scope. Verification
uses CLI/capture paths and does not rerun the blocked TUI inspection. Privileged
interface tests require separate permission if they must run outside the sandbox.

Validation passed: full sniff/DNS/HTTP/TLS/email package tests, focused capture,
virtual-interface and VoIP tests, replay race checks, `go vet` for affected
packages, and `make build`. CLI smoke checks verified two-pass packet/PCAP/log
retention, empty filtered loop termination, live-input rejection and graceful
SIGINT during an inter-pass delay. All 5,712 current messages are translated in
each catalog; manual tests and all three editions build successfully.

The bounded closure review is complete. Its documentation finding was corrected
and checked in every language. No runtime findings remain. Actual privileged
TAP/TUN creation was not exercised; lifecycle and timing checks used mock sinks.
