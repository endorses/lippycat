# Bound SIP IP-pair retention

The reported SIP pair leak is present: cleanup has no production caller.
Replace the unbounded map with a mutex-protected map and a list ordered by
last SIP observation. Refreshes move pairs to the back, so expiry and capacity
eviction remove the oldest observation without scanning live entries.

- [x] Bound each sweep to 1,024 removals and retain the 30-minute TTL.
- [x] Add `detector.max_sip_ip_pairs` (default 100,000; nonpositive values use
      the default) and entry, TTL eviction, and capacity eviction statistics.
- [x] Run cleanup every second through the detector lifecycle and join it on shutdown.
- [x] Verify idle expiry, bounded work, live/reversed pairs, refresh ordering,
      capacity enforcement, concurrent access, and lifecycle behavior.
- [x] Format and run detector tests with the race detector.

Validation passed: `GOCACHE=/tmp/lippycat-go-cache go test -race ./internal/pkg/detector/...`.
Code, tests, documentation, and this completed plan are committed together.
