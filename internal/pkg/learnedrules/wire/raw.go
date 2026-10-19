package wire

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
)

func AcceptEvidenceVersions(offered []uint32) []uint32 {
	for _, v := range offered {
		if v == EvidenceVersion {
			return []uint32{EvidenceVersion}
		}
	}
	return nil
}

// ValidateBatchEvidence runs before custody or forwarding: protobuf unknown-field
// preservation alone cannot establish that a receiver validates evidence.
func ValidateBatchEvidence(batch *data.PacketBatch, accepted []uint32) error {
	if batch == nil {
		return learnedrules.ErrInvalid
	}
	supported := len(AcceptEvidenceVersions(accepted)) > 0
	for _, packet := range batch.Packets {
		if packet == nil {
			return learnedrules.ErrInvalid
		}
		if packet.LearnedCaptureEvidence == nil {
			continue
		}
		if !supported {
			return learnedrules.ErrUnsupported
		}
		if len(packet.CaptureSelectionProof) > 0 {
			return learnedrules.ErrInvalid
		}
		if err := ValidateEvidence(packet.LearnedCaptureEvidence, DefaultEvidenceLimits); err != nil {
			return err
		}
	}
	return nil
}

// PacketStream rejects evidence-dependent packets when readiness did not
// acknowledge the typed format. It never rewrites a packet into legacy evidence.
type PacketStream struct {
	data.DataService_StreamPacketsClient
	versions []uint32
}

func NewPacketStream(stream data.DataService_StreamPacketsClient, versions []uint32) *PacketStream {
	return &PacketStream{DataService_StreamPacketsClient: stream, versions: AcceptEvidenceVersions(versions)}
}
func (s *PacketStream) LearnedEvidenceVersions() []uint32 {
	return append([]uint32(nil), s.versions...)
}
func (s *PacketStream) Send(batch *data.PacketBatch) error {
	if err := ValidateBatchEvidence(batch, s.versions); err != nil {
		return err
	}
	return s.DataService_StreamPacketsClient.Send(batch)
}
