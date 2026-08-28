# Pipeline Operation Safety

This document defines where normalized pipeline operations may run and how
`PacketEnvelope.Stages` must be interpreted. Composition roots and adapters use
these rules to avoid repeating stateful work after a topology boundary.

## Classification

| Operation | Stage capability | Classification | Rule |
|---|---|---|---|
| Link-layer/network decoding | `StageDecoded` | Idempotent | May run at either edge or center. Reuse the decoded packet when the stage is already present. |
| IP defragmentation | `StageDefragmented` | Edge-safe, not idempotent | Run once at the first processing location. Do not defragment an envelope carrying this capability again. |
| Protocol detection | `StageDetected` | Edge-safe and idempotent | Hunters may detect before forwarding. Central processing may run it only when the capability is absent. |
| TCP stream reassembly | `StageReassembled` | Topology-owned, not idempotent | Exactly one reassembly owner processes a flow. A processor must not reassemble a stream already reassembled upstream. |
| Protocol analysis | `StageAnalyzed` | Edge-safe for hunter-supported analyzers | Preserve upstream metadata and analyze centrally only when the capability is absent or when a distinct central-only enrichment is required. |
| Application/LI filter matching | `StageFiltered` | Edge-safe, not generally idempotent | Preserve matched filter IDs. Re-evaluate only when filter policy explicitly changes at a new topology boundary. |
| Call correlation and global call lifecycle | none | Central-only | Requires processor-wide state across hunters and must not be attributed as an edge stage. |
| Processor connection accounting and structured-log emission | none | Central-only | Requires processor policy and sink ownership. |
| PCAP/session writing, subscriber broadcast, upstream delivery, and LI delivery | none | Central-only sink operations | Delivery is performed by the owning composition root and is never inferred from packet metadata. |

## Provenance rules

- A stage bit records an operation that actually ran; it is not inferred merely
  because similarly shaped metadata exists.
- The gRPC batch ingress adapter may attribute `StageDetected` and
  `StageAnalyzed` to hunter metadata because that boundary knows the metadata's
  upstream origin. Generic packet conversion must not make that inference.
- Matched filter IDs imply `StageFiltered`; empty IDs do not prove filtering did
  not run.
- Stage provenance is internal execution state and is not part of the existing
  protobuf wire contract. An egress followed by a new gRPC ingress reconstructs
  only capabilities evidenced by that boundary's metadata and filter IDs.
- Central enrichment must preserve the original metadata payload and existing
  stage bits. It may add a capability only after performing that operation.
