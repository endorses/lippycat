// Package offline provides bounded temporary storage and complete queries for
// finalized capture datasets, independent of presentation and packet analysis.
package offline

import "github.com/endorses/lippycat/internal/pkg/types"

// Summary is an immutable filter projection of a finalized logical packet. It
// owns its metadata and contains no raw bytes, bodies, headers, or full answers.
// Its private projection deliberately delegates field semantics to PacketDisplay
// instead of maintaining a second implementation of aliases and presence rules.
type Summary struct {
	ID     PacketID
	packet types.PacketDisplay
}

// NewSummary snapshots all fields currently observable by packet filters.
// Call only after deferred analyzer metadata updates have been finalized.
func NewSummary(id PacketID, p types.PacketDisplay) Summary {
	s := Summary{ID: id, packet: types.PacketDisplay{
		Timestamp: p.Timestamp, SrcIP: p.SrcIP, DstIP: p.DstIP,
		SrcPort: p.SrcPort, DstPort: p.DstPort, Protocol: p.Protocol,
		Transport: p.Transport, Length: p.Length, Info: p.Info,
		NodeID: p.NodeID, Interface: p.Interface, LinkType: p.LinkType,
	}}
	if v := p.VoIPData; v != nil {
		s.packet.VoIPData = &types.VoIPMetadata{
			User: v.User, From: v.From, To: v.To, CallID: v.CallID,
			Method: v.Method, Codec: v.Codec, FromTag: v.FromTag, ToTag: v.ToTag,
			IMSI: v.IMSI, IMEI: v.IMEI, Status: v.Status, IsRTP: v.IsRTP,
			SequenceNum: v.SequenceNum, SSRC: v.SSRC,
		}
	}
	if d := p.DNSData; d != nil {
		s.packet.DNSData = &types.DNSMetadata{
			QueryName: d.QueryName, QueryType: d.QueryType,
			QueryResponseTimeMs: d.QueryResponseTimeMs,
		}
		if len(d.Answers) > 0 {
			s.packet.DNSData.Answers = []types.DNSAnswer{{TTL: d.Answers[0].TTL}}
		}
	}
	if t := p.TLSData; t != nil {
		s.packet.TLSData = &types.TLSMetadata{SNI: t.SNI, JA3Fingerprint: t.JA3Fingerprint}
	}
	if h := p.HTTPData; h != nil {
		s.packet.HTTPData = &types.HTTPMetadata{Host: h.Host, Path: h.Path,
			Method: h.Method, StatusCode: h.StatusCode, ContentLength: h.ContentLength}
	}
	if p.EmailData != nil {
		s.packet.EmailData = &types.EmailMetadata{}
	}
	return s
}

func (s Summary) GetStringField(name string) string   { return s.packet.GetStringField(name) }
func (s Summary) GetNumericField(name string) float64 { return s.packet.GetNumericField(name) }
func (s Summary) HasField(name string) bool           { return s.packet.HasField(name) }
func (s Summary) RecordType() string                  { return s.packet.RecordType() }

// DisplayFields returns the scalar packet-list presentation fields without I/O.
// Metadata and raw bytes belong to Detail; this value cannot mutate the summary.
func (s Summary) DisplayFields() types.PacketDisplay {
	p := s.packet
	p.VoIPData, p.DNSData, p.TLSData, p.HTTPData, p.EmailData = nil, nil, nil, nil, nil
	return p
}
