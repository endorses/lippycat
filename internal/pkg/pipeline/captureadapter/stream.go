package captureadapter

import (
	"context"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// Stream converts local capture records to normalized envelopes without
// reordering them. The caller owns and closes output after Stream returns.
func Stream(ctx context.Context, input <-chan capture.PacketInfo, output chan<- *pipeline.PacketEnvelope, kind pipeline.SourceKind) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case info, ok := <-input:
			if !ok {
				return nil
			}
			envelope := FromPacketInfo(info, kind)
			select {
			case output <- envelope:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
