// Package grpcadapter is the only pipeline adapter that knows generated packet protobufs.
package grpcadapter

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/proto"
)

func FromCapturedPacket(p *data.CapturedPacket, source pipeline.SourceProvenance) (*pipeline.PacketEnvelope, error) {
	if p == nil {
		return nil, fmt.Errorf("convert captured packet: nil packet")
	}
	source.InterfaceName, source.InterfaceIndex = p.InterfaceName, p.InterfaceIndex
	e := &pipeline.PacketEnvelope{Data: append([]byte(nil), p.Data...), LinkType: layers.LinkType(p.LinkType), CaptureTime: time.Unix(0, p.TimestampNs), CaptureLength: int(p.CaptureLength), OriginalLength: int(p.OriginalLength), Source: source, MatchedFilterIDs: append([]string(nil), p.MatchedFilterIds...), TLSKeys: fromTLSKeys(p.TlsKeys)}
	if p.Metadata != nil {
		metadata, err := MetadataFromProto(p.Metadata)
		if err != nil {
			return nil, err
		}
		e.Metadata = metadata
	}
	if len(e.MatchedFilterIDs) > 0 {
		e.Stages = e.Stages.With(pipeline.StageFiltered)
	}
	return e, nil
}

// MetadataFromProto encodes analyzer metadata for storage on a transport-neutral
// envelope. Generated protobuf values must not escape the adapter boundary.
func MetadataFromProto(metadata *data.PacketMetadata) (*pipeline.Metadata, error) {
	if metadata == nil {
		return nil, nil
	}
	payload, err := proto.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode packet metadata: %w", err)
	}
	return &pipeline.Metadata{Protocol: metadata.Protocol, SourceIP: metadata.SrcIp, DestinationIP: metadata.DstIp, SourcePort: metadata.SrcPort, DestinationPort: metadata.DstPort, Transport: metadata.Transport, Info: metadata.Info, Details: cloneMap(metadata.Details), Encoding: pipeline.MetadataProtobuf, Payload: payload}, nil
}

func FromPacketBatch(b *data.PacketBatch) (*pipeline.PacketBatch, error) {
	if b == nil {
		return nil, fmt.Errorf("convert packet batch: nil batch")
	}
	source := pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: b.HunterId, BatchSequence: b.Sequence, BatchTimestamp: time.Unix(0, b.TimestampNs)}
	out := &pipeline.PacketBatch{Source: source, Sequence: b.Sequence, CreatedAt: source.BatchTimestamp, Packets: make([]*pipeline.PacketEnvelope, 0, len(b.Packets))}
	if b.Stats != nil {
		out.HasStats = true
		out.Stats = pipeline.BatchStats{TotalCaptured: b.Stats.TotalCaptured, FilteredMatched: b.Stats.FilteredMatched, Dropped: b.Stats.Dropped, BufferUsage: b.Stats.BufferUsage}
	}
	for i, p := range b.Packets {
		e, err := FromCapturedPacket(p, source)
		if err != nil {
			return nil, fmt.Errorf("convert packet %d: %w", i, err)
		}
		// Metadata on the gRPC ingress contract was produced upstream by the
		// hunter. Attribute those edge operations here, where the transport
		// topology is known, rather than in FromCapturedPacket (which is also
		// used to normalize locally and centrally enriched packets).
		if p.Metadata != nil {
			e.Stages = e.Stages.With(pipeline.StageDetected).With(pipeline.StageAnalyzed)
		}
		out.Packets = append(out.Packets, e)
	}
	return out, nil
}

func ToPacketBatch(b *pipeline.PacketBatch) (*data.PacketBatch, error) {
	if b == nil {
		return nil, fmt.Errorf("convert packet batch: nil batch")
	}
	out := &data.PacketBatch{HunterId: b.Source.NodeID, Sequence: b.Sequence, TimestampNs: unixNano(b.CreatedAt), Packets: make([]*data.CapturedPacket, 0, len(b.Packets))}
	if b.HasStats {
		out.Stats = &data.BatchStats{TotalCaptured: b.Stats.TotalCaptured, FilteredMatched: b.Stats.FilteredMatched, Dropped: b.Stats.Dropped, BufferUsage: b.Stats.BufferUsage}
	}
	for i, e := range b.Packets {
		p, err := ToCapturedPacket(e)
		if err != nil {
			return nil, fmt.Errorf("convert envelope %d: %w", i, err)
		}
		out.Packets = append(out.Packets, p)
	}
	return out, nil
}

func ToCapturedPacket(e *pipeline.PacketEnvelope) (*data.CapturedPacket, error) {
	if e == nil {
		return nil, fmt.Errorf("convert packet envelope: nil envelope")
	}
	p := &data.CapturedPacket{Data: append([]byte(nil), e.Data...), TimestampNs: unixNano(e.CaptureTime), CaptureLength: uint32(e.CaptureLength), OriginalLength: uint32(e.OriginalLength), InterfaceIndex: e.Source.InterfaceIndex, LinkType: uint32(e.LinkType), InterfaceName: e.Source.InterfaceName, MatchedFilterIds: append([]string(nil), e.MatchedFilterIDs...), TlsKeys: toTLSKeys(e.TLSKeys)} // #nosec G115 -- pcap lengths and link type are wire fields
	if e.Metadata != nil {
		if e.Metadata.Encoding != pipeline.MetadataProtobuf {
			return nil, fmt.Errorf("convert metadata: unsupported encoding %d", e.Metadata.Encoding)
		}
		p.Metadata = &data.PacketMetadata{}
		if err := proto.Unmarshal(e.Metadata.Payload, p.Metadata); err != nil {
			return nil, fmt.Errorf("decode packet metadata: %w", err)
		}
	}
	return p, nil
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromTLSKeys(k *data.TLSSessionKeys) *pipeline.TLSSessionKeys {
	if k == nil {
		return nil
	}
	return &pipeline.TLSSessionKeys{ClientRandom: append([]byte(nil), k.ClientRandom...), ServerRandom: append([]byte(nil), k.ServerRandom...), PreMasterSecret: append([]byte(nil), k.PreMasterSecret...), ClientHandshakeSecret: append([]byte(nil), k.ClientHandshakeTrafficSecret...), ServerHandshakeSecret: append([]byte(nil), k.ServerHandshakeTrafficSecret...), ClientTrafficSecret0: append([]byte(nil), k.ClientTrafficSecret_0...), ServerTrafficSecret0: append([]byte(nil), k.ServerTrafficSecret_0...), ExporterSecret: append([]byte(nil), k.ExporterSecret...), EarlyExporterSecret: append([]byte(nil), k.EarlyExporterSecret...), ClientEarlyTrafficSecret: append([]byte(nil), k.ClientEarlyTrafficSecret...), TLSVersion: k.TlsVersion, CipherSuite: k.CipherSuite, SourceIP: k.SrcIp, SourcePort: k.SrcPort, DestinationIP: k.DstIp, DestinationPort: k.DstPort}
}
func toTLSKeys(k *pipeline.TLSSessionKeys) *data.TLSSessionKeys {
	if k == nil {
		return nil
	}
	return &data.TLSSessionKeys{ClientRandom: append([]byte(nil), k.ClientRandom...), ServerRandom: append([]byte(nil), k.ServerRandom...), PreMasterSecret: append([]byte(nil), k.PreMasterSecret...), ClientHandshakeTrafficSecret: append([]byte(nil), k.ClientHandshakeSecret...), ServerHandshakeTrafficSecret: append([]byte(nil), k.ServerHandshakeSecret...), ClientTrafficSecret_0: append([]byte(nil), k.ClientTrafficSecret0...), ServerTrafficSecret_0: append([]byte(nil), k.ServerTrafficSecret0...), ExporterSecret: append([]byte(nil), k.ExporterSecret...), EarlyExporterSecret: append([]byte(nil), k.EarlyExporterSecret...), ClientEarlyTrafficSecret: append([]byte(nil), k.ClientEarlyTrafficSecret...), TlsVersion: k.TLSVersion, CipherSuite: k.CipherSuite, SrcIp: k.SourceIP, SrcPort: k.SourcePort, DstIp: k.DestinationIP, DstPort: k.DestinationPort}
}
