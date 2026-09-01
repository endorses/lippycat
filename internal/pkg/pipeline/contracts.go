// Package pipeline contains protocol- and transport-neutral packet pipeline contracts.
package pipeline

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SourceKind identifies the topology adapter that produced a packet.
type SourceKind uint8

const (
	SourceUnknown SourceKind = iota
	SourceLiveCapture
	SourcePCAPReplay
	SourceGRPC
)

// SourceProvenance describes where a packet was observed. Batch fields are set
// only for transports that batch packets.
type SourceProvenance struct {
	Kind           SourceKind
	NodeID         string
	InterfaceName  string
	InterfaceIndex uint32
	BatchSequence  uint64
	BatchTimestamp time.Time
}

// Stage is a named pipeline capability. It is deliberately a bit set rather
// than an open-ended collection of strings.
type Stage uint32

const (
	StageDecoded Stage = 1 << iota
	StageDefragmented
	StageDetected
	StageReassembled
	StageAnalyzed
	StageFiltered
)

// StageProvenance records operations already performed upstream.
type StageProvenance uint32

func (p StageProvenance) Has(stage Stage) bool { return uint32(p)&uint32(stage) != 0 }
func (p StageProvenance) With(stage Stage) StageProvenance {
	return StageProvenance(uint32(p) | uint32(stage))
}

// MetadataEncoding identifies a stable transport representation retained at an
// ingress boundary. Adapters own encoding/decoding; pipeline stages use Summary.
type MetadataEncoding uint8

const (
	MetadataNone MetadataEncoding = iota
	MetadataProtobuf
)

// MetadataSummary exposes routing fields without coupling the pipeline to a
// generated transport package. Payload preserves every transport metadata field.
type Metadata struct {
	Protocol, SourceIP, DestinationIP, Transport, Info string
	SourcePort, DestinationPort                        uint32
	Details                                            map[string]string
	Encoding                                           MetadataEncoding
	Payload                                            []byte
}

// TLSSessionKeys is transport-neutral key material associated with a packet.
type TLSSessionKeys struct {
	ClientRandom, ServerRandom, PreMasterSecret                   []byte
	ClientHandshakeSecret, ServerHandshakeSecret                  []byte
	ClientTrafficSecret0, ServerTrafficSecret0                    []byte
	ExporterSecret, EarlyExporterSecret, ClientEarlyTrafficSecret []byte
	TLSVersion, CipherSuite, SourcePort, DestinationPort          uint32
	SourceIP, DestinationIP                                       string
}

// PacketEnvelope is the normalized unit passed between ingress and stages.
type PacketEnvelope struct {
	Data             []byte
	LinkType         layers.LinkType
	CaptureTime      time.Time
	CaptureLength    int
	OriginalLength   int
	Source           SourceProvenance
	Stages           StageProvenance
	MatchedFilterIDs []string
	Metadata         *Metadata
	TLSKeys          *TLSSessionKeys

	decodeOnce sync.Once
	packet     gopacket.Packet
}

// PacketBatch preserves transport ordering provenance while keeping packets normalized.
type PacketBatch struct {
	Source    SourceProvenance
	Sequence  uint64
	CreatedAt time.Time
	Packets   []*PacketEnvelope
	HasStats  bool
	Stats     BatchStats
}

type BatchStats struct {
	TotalCaptured, FilteredMatched, Dropped uint64
	CaptureBufferRegularDrops               uint64
	CaptureBufferSIPDrops                   uint64
	BatchChannelDrops                       uint64
	BufferUsage                             uint32
}

// NewDecodedPacketEnvelope creates an envelope that retains an already-decoded
// packet. The packet and its data must remain immutable after this call. Keeping
// the packet avoids copying and decoding local capture records a second time.
func NewDecodedPacketEnvelope(packet gopacket.Packet, linkType layers.LinkType) *PacketEnvelope {
	e := &PacketEnvelope{LinkType: linkType}
	if packet == nil {
		return e
	}

	e.Data = packet.Data()
	if metadata := packet.Metadata(); metadata != nil {
		e.CaptureTime = metadata.Timestamp
		e.CaptureLength = metadata.CaptureLength
		e.OriginalLength = metadata.Length
	}
	e.decodeOnce.Do(func() {
		e.packet = packet
	})
	e.Stages = e.Stages.With(StageDecoded)
	return e
}

// Packet lazily decodes the captured bytes and returns the same packet thereafter.
func (e *PacketEnvelope) Packet() gopacket.Packet {
	if e == nil {
		return nil
	}
	e.decodeOnce.Do(func() {
		e.packet = gopacket.NewPacket(e.Data, e.LinkType, gopacket.NoCopy)
		e.packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
			Timestamp:     e.CaptureTime,
			CaptureLength: e.CaptureLength,
			Length:        e.OriginalLength,
		}
		e.Stages = e.Stages.With(StageDecoded)
	})
	return e.packet
}

// Outcome distinguishes normal filtering and pressure from delivery failures.
type Outcome uint8

const (
	OutcomeAccepted Outcome = iota
	OutcomeFiltered
	OutcomeDropped
	OutcomeRetryableFailure
	OutcomePermanentFailure
	OutcomeShutdown
)

// DropReason attributes bounded-data loss.
type DropReason uint8

const (
	DropNone DropReason = iota
	DropQueueFull
	DropBufferFull
	DropRateLimited
	DropExpired
	DropShutdown
)

// Result is returned by stages and sinks. Err is set for actionable failures;
// intentionally filtered and pressure-drop outcomes need not carry an error.
type Result struct {
	Outcome    Outcome
	DropReason DropReason
	Err        error
}
