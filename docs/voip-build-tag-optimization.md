# VoIP Build Tag Architecture

This document records the current build-tag boundary for VoIP functionality.
The earlier optimization proposal described standalone VoIP capture-engine and
writer files that were removed during pipeline unification.

## Current Design

VoIP capture enters the shared processor pipeline through packet sources:

- `internal/pkg/processor/source.LocalSource` captures local traffic for tap.
- `internal/pkg/processor/source.GRPCSource` receives traffic from hunters.
- `cmd/sniff` adapts local packets into the shared pipeline directly.
- `internal/pkg/voip/processor.SourceAdapter` supplies VoIP-specific source
  processing without maintaining a second standalone capture engine.

The transport-neutral `pipeline.PacketEnvelope` is the authoritative packet
representation. `source.PacketBatch.Packets` remains only as a temporary
compatibility view for processor consumers that have not completed migration.

## Build Tags

Command registration remains controlled by the root build variants (`all`,
`hunter`, `processor`, `tap`, `cli`, and `tui`). CUDA implementation files use
the `cuda` tag, with non-CUDA stubs preserving ordinary builds.

Do not add build tags to individual shared VoIP pipeline files merely to reduce
binary size. Their dependencies and ownership should instead follow the shared
pipeline boundaries, allowing Go dead-code elimination to remove unreachable
features from specialized binaries.

## Verification

When changing these boundaries, verify the supported build matrix:

```bash
make binaries
go test -tags=all ./...
go test -tags=hunter ./...
go test -tags=cli ./...
go test -tags=processor ./...
go test -tags=tui ./...
```

CUDA builds additionally require a configured CUDA toolchain and should be
verified in an appropriate environment.
