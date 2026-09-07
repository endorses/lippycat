# Remaining VoIP capture opening costs

Reduce the remaining completed-open costs on `gtest6.pcap` after the call registry
and metadata boundary fixes. Preserve normalization, ordering, protocol metadata,
integrity checks and resource limits; keep preexisting edits separate.

- [x] Profile the current implementation and identify avoidable remaining work.
- [x] Prototype measured improvements and retain only demonstrated wins.
- [x] Independently verify correctness, resource behavior and relevant race tests.
- [x] Compare both private captures, rebuild, and document measured results and limits.

Commit the verified implementation, tests, measurements and completed plan.

Results: completed VoIP opening improved from 7.643 to 5.398 seconds (median of
three paired runs); mixed traffic measured 3.106 versus 3.144 seconds. Both final
private-capture parity checks, focused and broad race tests, independent isolated
verification, and the build passed. See
[measurements and limitations](../research/watch-file-voip-remaining-costs.md).
