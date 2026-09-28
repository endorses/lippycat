# TCP SIP stream retention after connection bursts

**Source:** `/home/grischa/2026-09-28-tcp-sip-stream-retention.md`

**Status:** Implementation verified; commit pending

## Objective

Release completed SIP stream state retained by the in-tree TCP reassembly pool
after a connection burst. Give `tap voip` and `hunt voip` the existing optional
TCP stream processor limit, enforce that limit on rearm, and make its behavior
clear to operators.

The production report observed about 240,000 live stream/channel allocations
after the burst while far fewer stream goroutines were running. The code path
to fix is `internal/pkg/reassembly`, which keeps removed connections and their
stream references in its free list. Transparent huge pages may separately keep
RSS high after the Go runtime releases heap; the report does not quantify that
contribution.

## Design constraints

- [x] Keep `ReassembledSG` non-blocking and preserve SIP parsing, connection
      reuse, assembler flushing, and graceful shutdown behavior.
- [x] Release stream references only after reassembly completion. Account for
      concurrent assemble, flush, and free-list reuse when choosing lock order;
      do not clear `dataChan` from the stream goroutine without synchronizing
      with `ReassemblyComplete`.
- [x] Leave connection slab reclamation out of this change. `StreamPool.all`
      retains slabs, so trimming `free` alone would not release them. Revisit
      slab retention only if separate evidence shows it matters after the
      stream-reference fix.
- [x] Keep `MaxStreams = 0` as unlimited. Describe a positive value as a cap on
      active buffered SIP stream processors, not on TCP connections, pool
      capacity, or total process memory. Limit rejection intentionally drops
      that stream's SIP data.
- [x] Use synthetic traffic and identifiers in reproduction and tests. Do not
      introduce an absolute RSS, throughput, or latency acceptance target.

## 1. Release completed streams from the reassembly pool

- [x] Update `internal/pkg/reassembly/memory.go` and the relevant assembler
      removal paths in `tcpassembly.go` so a removed connection no longer holds
      `c2s.stream` or `s2c.stream` when placed on the free list. Preserve the
      connection object for reuse. Ensure a processing goroutine can retain its
      stream until it exits without the pool keeping it alive afterward.
- [x] Review the existing `conn.mu`/pool mutex order at both removal sites and
      at `getConnection` before changing them. Avoid leaving a caller with a
      connection whose stream references were cleared or whose slot was reused.
- [x] Add focused `internal/pkg/reassembly` tests for FIN/RST closure, idle
      flush, and free-list reuse. Assert that removed entries have no stream
      references and a reused entry receives a fresh stream in both directions.
- [x] Exercise concurrent assemble/flush/removal with the race detector and
      verify that the same stream receives one completion notification.

## 2. Make the optional processor limit effective in VoIP tap and hunt

- [x] Add `--tcp-max-streams` to `tap voip` and `hunt voip`, bound to the shared
      `voip.max_streams` setting. Resolve each command's effective value using
      established flag/config precedence and pass a local `voip.Config` copy to
      `NewSipStreamFactoryWithConfig`; do not mutate global VoIP configuration.
- [x] Validate negative values before starting capture. Keep the default at
      zero, and make the flag help and error text say that positive values can
      reject new TCP SIP streams.
- [x] Make `bufferedSIPStream.rearm` reserve a factory slot before restarting
      its processing goroutine. If no slot is available, leave the old reader
      stopped, do not queue the new chunk, and record a limit rejection using
      the existing stream-limit accounting. Preserve shutdown and `finished`
      state handling, and do not double-count a successfully restarted stream.
- [x] Add focused VoIP tests for cap enforcement across concurrent factory
      creation and 4-tuple rearm, including rejection followed by later
      capacity becoming available. Verify that the active count returns to
      zero after completion/shutdown.
- [x] Add tap and hunt command/config contract tests for default, positive,
      negative, config-file, and flag-override values. Verify each command
      passes the resolved limit to its stream factory.

## 3. Operator wording and documentation

- [x] Reword the `MaxGoroutines` log message in `internal/pkg/voip/tcp_metrics.go`
      as an advisory threshold, and correct any nearby comments or help text
      that imply enforcement. Keep its pressure/telemetry meaning unchanged.
- [x] Document `--tcp-max-streams` and `voip.max_streams` in the tap and hunt
      command READMEs and the manual's configuration and command references.
      Explain the unlimited default, intentional stream rejection at a positive
      limit, and the fact that discarded connections can still occupy pool
      entries. Correct sniff wording if it still calls `MaxGoroutines` a cap.
- [x] Add a short operational note to `docs/PERFORMANCE.md`: on hosts using
      THP `always`, `GODEBUG=disablethp=1` is a Go heap workaround whose effect
      can be checked against post-burst RSS and runtime memory metrics. Link
      the Go GC guidance and avoid attributing a fixed amount of the reported
      RSS gap to THP.

## 4. Verification and closure

- [x] Run focused reassembly and VoIP tests, then the affected tap, hunt, and
      sniff command tests under their build tags. Run race tests for the pool
      removal and stream rearm paths. Build the affected specialized variants.
- [x] Reproduce a short-lived synthetic SIP-over-TCP burst through the
      reassembly engine. After flush, worker exit, and GC, verify free entries
      have nil stream references and the retained channel allocations fall.
      Treat heap and RSS measurements as diagnostic evidence, without a new
      numerical pass/fail gate.
- [ ] Format changed files, review the diff, mark only verified plan tasks
      complete, and commit the code, documentation, and updated plan together.

An operator can trial the THP workaround independently of code deployment.
Production RSS comparison is useful follow-up evidence, not a prerequisite for
closing the code change.
