# Pipeline stage capabilities

Pipeline provenance uses the typed `pipeline.Stage` bit set. Adapters must mark a
stage only when its output is present and valid.

| Operation | Placement | Repeatability |
|---|---|---|
| Link/network decode | Edge or central | Idempotent; central may decode lazily |
| IP defragmentation | Edge for local capture, otherwise central | Not safe to repeat |
| Signature detection | Edge or central | Idempotent, but skip when upstream result is preserved |
| TCP reassembly | Owner of the stream state | Not safe to repeat |
| Protocol analysis | Edge or central | Enrichment is allowed; do not replace preserved metadata |
| Application/LI filtering | Edge | Not safe to repeat as selection policy may differ |
| Cross-hunter correlation, LI delivery, processor output policy | Central only | Controlled by the owning state service or sink |

Conversion functions between generated packet protobuf values and pipeline
contracts are confined to `pipeline/grpcadapter`. During the staged migration,
some processor analyzers still operate on a compatibility protobuf view;
`source.PacketBatch.SyncEnvelopesFromPackets` merges their changes at the
explicit egress boundary, and egress serialization reads only the authoritative
envelopes. The normalized envelope retains a typed
metadata summary for routing and the lossless encoded transport metadata for
forwarding. Protocol analyzers emit the domain result types in
`pipeline/results.go`; transport egress performs wire conversion.
